using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using OtpNet;

class Program
{
    static async Task Main(string[] args)
    {
        // Debug: Show what args we received
        Console.WriteLine($"Received {args.Length} arguments:");
        for (int i = 0; i < args.Length; i++)
        {
            Console.WriteLine($"  args[{i}] = '{args[i]}'");
        }

        if (args.Length < 2 || args[0] != "--json")
        {
            Console.WriteLine("Usage: dotnet run -- --json '{\"firstname\":\"John\", ...}'");
            Console.WriteLine("Or: dotnet run -- --json \"{\\\"firstname\\\":\\\"John\\\", ...}\"");
            return;
        }

        string clientJson = args[1];
        Console.WriteLine($"Raw JSON input length: {clientJson.Length}");
        Console.WriteLine($"First 100 chars: {clientJson.Substring(0, Math.Min(100, clientJson.Length))}");

        // Try to clean the JSON if it has issues
        if (clientJson.StartsWith("'") && clientJson.EndsWith("'"))
        {
            Console.WriteLine("Removing single quotes from JSON...");
            clientJson = clientJson.Trim('\'');
        }

        // Try to parse JSON to validate it
        try
        {
            var testParse = JsonSerializer.Deserialize<JsonElement>(clientJson);
            Console.WriteLine("✓ JSON is valid");
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"❌ JSON parsing error: {ex.Message}");
            Console.WriteLine($"Attempting to fix JSON...");
            
            // Try to fix common issues
            clientJson = clientJson.Replace("'", "\"");
            
            // Try parsing again
            try
            {
                var testParse = JsonSerializer.Deserialize<JsonElement>(clientJson);
                Console.WriteLine("✓ Fixed JSON is valid");
            }
            catch (JsonException ex2)
            {
                Console.WriteLine($"❌ Still invalid after fixing: {ex2.Message}");
                Console.WriteLine("Please check your JSON format");
                Environment.Exit(1);
            }
        }

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? throw new Exception("MIJNDIAD_TENANT not set");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") ?? throw new Exception("MIJNDIAD_USERNAME not set");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") ?? throw new Exception("MIJNDIAD_PASSWORD not set");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") ?? throw new Exception("MIJNDIAD_TOTP_SECRET not set");
        var totp = GenerateTotp(totpSecret);

        var baseUrl = $"https://{tenant}.mijndiad.nl";

        Console.WriteLine("\n== MijnDiAd Auto-Login & Client Creation ==");
        Console.WriteLine($"Running on: {Environment.MachineName}");
        Console.WriteLine($"Base URL: {baseUrl}");

        // Configure HttpClient with cookies
        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            UseDefaultCredentials = false,
            AutomaticDecompression = DecompressionMethods.All,
            AllowAutoRedirect = false
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36");
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("Accept-Language", "nl");

        try
        {
            // 1️⃣ Fetch login page
            Console.WriteLine("\n[1/8] Fetching login page...");
            var loginPageResponse = await client.GetAsync($"{baseUrl}/login");
            loginPageResponse.EnsureSuccessStatusCode();
            var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"  Status: {loginPageResponse.StatusCode}");

            // 2️⃣ Extract CSRF token
            Console.WriteLine("\n[2/8] Extracting CSRF token...");
            var csrfMatch = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!csrfMatch.Success)
            {
                Console.WriteLine("❌ CSRF token not found");
                Environment.Exit(1);
            }
            var csrfToken = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  ✓ CSRF token extracted");

            // 3️⃣ Login
            Console.WriteLine("\n[3/8] Logging in...");
            Console.WriteLine($"  Generated TOTP: {totp}");

            var loginPayload = new
            {
                email = username,
                password = password,
                totp_code = totp
            };
            
            var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");
            
            var loginRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/login")
            {
                Content = loginContent
            };
            
            loginRequest.Headers.Add("X-CSRF-TOKEN", csrfToken);
            loginRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            loginRequest.Headers.Add("Origin", baseUrl);
            loginRequest.Headers.Add("Referer", $"{baseUrl}/login");
            
            var loginResponse = await client.SendAsync(loginRequest);
            var loginBody = await loginResponse.Content.ReadAsStringAsync();

            Console.WriteLine($"  Login Response: {(int)loginResponse.StatusCode}");
            
            if (!loginResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Login failed: {(int)loginResponse.StatusCode}");
                Console.WriteLine($"Response: {loginBody}");
                Environment.Exit(1);
            }
            Console.WriteLine("  ✓ Login successful");

            // 4️⃣ Get Sanctum CSRF cookie
            Console.WriteLine("\n[4/8] Getting Sanctum CSRF cookie...");
            var sanctumResponse = await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
            Console.WriteLine($"  Sanctum Response: {sanctumResponse.StatusCode}");
            sanctumResponse.EnsureSuccessStatusCode();
            Console.WriteLine("  ✓ Sanctum CSRF cookie refreshed");

            // 5️⃣ Add locale cookie
            Console.WriteLine("\n[5/8] Setting locale cookie...");
            cookieContainer.Add(new Uri(baseUrl), new Cookie("locale", "nl"));
            Console.WriteLine("  ✓ Locale cookie set to 'nl'");

            // 6️⃣ Verify session with API user endpoint
            Console.WriteLine("\n[6/8] Verifying authenticated session...");
            
            // Get plain XSRF token from cookies (not URL-decoded)
            string plainXsrfToken = "";
            var cookies = cookieContainer.GetCookies(new Uri(baseUrl));
            foreach (Cookie c in cookies)
            {
                if (c.Name == "XSRF-TOKEN")
                {
                    plainXsrfToken = c.Value;
                    break;
                }
            }

            if (string.IsNullOrEmpty(plainXsrfToken))
            {
                Console.WriteLine("❌ XSRF-TOKEN cookie not found");
                Environment.Exit(1);
            }

            Console.WriteLine($"  Plain XSRF token: {plainXsrfToken.Substring(0, Math.Min(20, plainXsrfToken.Length))}...");

            var userRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/user");
            userRequest.Headers.Add("X-CSRF-Token", plainXsrfToken);
            userRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            userRequest.Headers.Add("Referer", $"{baseUrl}/");
            
            var userResponse = await client.SendAsync(userRequest);
            var userBody = await userResponse.Content.ReadAsStringAsync();
            
            Console.WriteLine($"  User API Response: {userResponse.StatusCode}");
            
            if (!userResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Session verification failed");
                Console.WriteLine($"Response: {userBody}");
                Environment.Exit(1);
            }
            
            Console.WriteLine($"  ✓ Session verified");

            // 7️⃣ Parse client JSON and convert to form data
            Console.WriteLine("\n[7/8] Preparing form data...");
            
            // Create a simpler, more robust form data builder
            var formData = BuildFormDataFromJson(clientJson);
            Console.WriteLine($"  Form data fields prepared: {formData.Count()}");

            // 8️⃣ Create client with MULTIPART/FORM-DATA
            Console.WriteLine("\n[8/8] Creating client...");
            
            // Build cookie header
            string cookieHeader = cookieContainer.GetCookieHeader(new Uri(baseUrl));
            Console.WriteLine($"  Cookie header: {cookieHeader.Length} chars");

            var createClientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            // Headers matching browser request
            createClientRequest.Headers.Add("X-CSRF-Token", plainXsrfToken);
            createClientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            createClientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            createClientRequest.Headers.Add("Origin", baseUrl);
            createClientRequest.Headers.Add("Cookie", cookieHeader);
            createClientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            createClientRequest.Headers.Add("Accept-Language", "nl");

            Console.WriteLine($"  Sending POST to {baseUrl}/api/clients");
            Console.WriteLine($"  Content-Type: {formData.Headers.ContentType}");

            var clientResponse = await client.SendAsync(createClientRequest);
            var clientResponseBody = await clientResponse.Content.ReadAsStringAsync();

            Console.WriteLine($"\n=== CLIENT CREATION RESPONSE ===");
            Console.WriteLine($"Status: {(int)clientResponse.StatusCode} ({clientResponse.StatusCode})");
            
            if (!string.IsNullOrEmpty(clientResponseBody))
            {
                try
                {
                    var json = JsonSerializer.Deserialize<JsonElement>(clientResponseBody);
                    var formatted = JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true });
                    Console.WriteLine($"Response:\n{formatted}");
                }
                catch (JsonException)
                {
                    Console.WriteLine($"Response: {clientResponseBody}");
                }
            }

            if (clientResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
            }
            else
            {
                Console.WriteLine("\n❌ Client creation failed");
                Environment.Exit(1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ UNEXPECTED ERROR: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
            Environment.Exit(1);
        }
    }

    // Simpler, more robust form data builder
    static MultipartFormDataContent BuildFormDataFromJson(string json)
    {
        var formData = new MultipartFormDataContent();
        
        try
        {
            var data = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
            
            // Helper to add form field
            void AddField(string name, object value)
            {
                string stringValue = value?.ToString() ?? "";
                formData.Add(new StringContent(stringValue), name);
            }

            // Add simple fields
            var simpleFields = new[] { 
                "salutation", "firstname", "lastname", "gender", "date_of_birth",
                "date_of_intake", "email", "mobilenumber", "reminder", "confirmation",
                "invoice_relation_id", "invoice_send_method", "is_active",
                "different_post_address", "allow_dubble_email"
            };

            foreach (var field in simpleFields)
            {
                if (data.TryGetValue(field, out object value))
                {
                    if (value is JsonElement element)
                    {
                        AddField(field, GetStringFromElement(element));
                    }
                    else
                    {
                        AddField(field, value);
                    }
                }
            }

            // Handle nested address object
            if (data.TryGetValue("address", out object addrObj) && addrObj is JsonElement addrElement)
            {
                if (addrElement.ValueKind == JsonValueKind.Object)
                {
                    var addrDict = JsonSerializer.Deserialize<Dictionary<string, object>>(addrElement.GetRawText());
                    foreach (var kvp in addrDict)
                    {
                        if (kvp.Value is JsonElement element)
                        {
                            AddField($"address[{kvp.Key}]", GetStringFromElement(element));
                        }
                        else
                        {
                            AddField($"address[{kvp.Key}]", kvp.Value);
                        }
                    }
                }
            }

            // Handle invoice_address
            if (data.TryGetValue("invoice_address", out object invAddrObj) && invAddrObj is JsonElement invAddrElement)
            {
                if (invAddrElement.ValueKind == JsonValueKind.Object)
                {
                    var invAddrDict = JsonSerializer.Deserialize<Dictionary<string, object>>(invAddrElement.GetRawText());
                    foreach (var kvp in invAddrDict)
                    {
                        if (kvp.Value is JsonElement element)
                        {
                            AddField($"invoice_address[{kvp.Key}]", GetStringFromElement(element));
                        }
                        else
                        {
                            AddField($"invoice_address[{kvp.Key}]", kvp.Value);
                        }
                    }
                }
            }

            // Handle arrays - add empty fields if needed
            formData.Add(new StringContent(""), "client_attributes[]");
            
            // Handle null client_group_ids
            formData.Add(new StringContent(""), "client_group_ids");
            
            return formData;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error building form data: {ex.Message}");
            throw;
        }
    }

    static string GetStringFromElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? "",
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "1",
            JsonValueKind.False => "0",
            JsonValueKind.Null => "",
            _ => element.ToString()
        };
    }

    // TOTP generation
    static string GenerateTotp(string base32Secret)
    {
        if (string.IsNullOrEmpty(base32Secret)) return "000000";
        
        try
        {
            var secretKey = Base32Encoding.ToBytes(base32Secret);
            var totp = new Totp(secretKey);
            return totp.ComputeTotp();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️  TOTP generation error: {ex.Message}");
            return "123456";
        }
    }
}
