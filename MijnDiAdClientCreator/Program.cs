using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using OtpNet;

class Program
{
    static async Task Main(string[] args)
    {
        string clientJson;
        
        if (args.Length >= 2 && args[0] == "--json-file")
        {
            string filePath = args[1];
            Console.WriteLine($"Reading JSON from file: {filePath}");
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"❌ File not found: {filePath}");
                Environment.Exit(1);
            }
            clientJson = await File.ReadAllTextAsync(filePath);
        }
        else if (File.Exists("client_data.json"))
        {
            Console.WriteLine("Reading JSON from default file: client_data.json");
            clientJson = await File.ReadAllTextAsync("client_data.json");
        }
        else
        {
            Console.WriteLine("Usage: dotnet run -- --json-file data.json");
            return;
        }

        // Validate JSON
        try
        {
            var testParse = JsonSerializer.Deserialize<JsonElement>(clientJson);
            Console.WriteLine("✓ JSON is valid");
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"❌ JSON parsing error: {ex.Message}");
            Environment.Exit(1);
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
            Console.WriteLine("\n[1/11] Fetching login page...");
            var loginPageResponse = await client.GetAsync($"{baseUrl}/login");
            loginPageResponse.EnsureSuccessStatusCode();
            var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

            // 2️⃣ Extract CSRF token from HTML meta tag
            Console.WriteLine("\n[2/11] Extracting CSRF token from HTML...");
            var csrfMatch = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!csrfMatch.Success)
            {
                Console.WriteLine("❌ CSRF token not found in HTML");
                Environment.Exit(1);
            }
            var htmlCsrfToken = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  ✓ HTML CSRF token extracted");

            // 3️⃣ Login with HTML CSRF token
            Console.WriteLine("\n[3/11] Logging in...");
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
            
            loginRequest.Headers.Add("X-CSRF-TOKEN", htmlCsrfToken);
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
            Console.WriteLine("\n[4/11] Getting Sanctum CSRF cookie...");
            var sanctumResponse = await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
            sanctumResponse.EnsureSuccessStatusCode();
            Console.WriteLine("  ✓ Sanctum CSRF cookie refreshed");

            // 5️⃣ Add locale cookie
            Console.WriteLine("\n[5/11] Setting locale cookie...");
            cookieContainer.Add(new Uri(baseUrl), new Cookie("locale", "nl"));
            Console.WriteLine("  ✓ Locale cookie set to 'nl'");

            // 6️⃣ Extract cookies
            Console.WriteLine("\n[6/11] Extracting cookies...");
            string cookieXsrfToken = "";
            var cookies = cookieContainer.GetCookies(new Uri(baseUrl));
            foreach (Cookie c in cookies)
            {
                if (c.Name == "XSRF-TOKEN")
                {
                    cookieXsrfToken = c.Value;
                    break;
                }
            }

            if (string.IsNullOrEmpty(cookieXsrfToken))
            {
                Console.WriteLine("❌ XSRF-TOKEN cookie not found");
                Environment.Exit(1);
            }

            Console.WriteLine($"  ✓ Cookie XSRF token extracted");

            // 7️⃣ Verify session with API user endpoint
            Console.WriteLine("\n[7/11] Verifying authenticated session...");

            var userRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/user");
            userRequest.Headers.Add("X-CSRF-Token", cookieXsrfToken);
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

            // 8️⃣ CRITICAL: Load the clients create page (like a browser does)
            Console.WriteLine("\n[8/11] Loading clients create page to establish context...");
            var createPageRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/clients/create");
            createPageRequest.Headers.Add("X-CSRF-Token", cookieXsrfToken);
            createPageRequest.Headers.Add("Referer", $"{baseUrl}/clients");
            
            var createPageResponse = await client.SendAsync(createPageRequest);
            var createPageHtml = await createPageResponse.Content.ReadAsStringAsync();
            
            Console.WriteLine($"  Create page Response: {createPageResponse.StatusCode}");
            
            // Extract NEW CSRF token from the create page
            var newCsrfMatch = Regex.Match(createPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (newCsrfMatch.Success)
            {
                htmlCsrfToken = newCsrfMatch.Groups[1].Value;
                Console.WriteLine($"  ✓ Updated CSRF token from create page");
            }

            // 9️⃣ Parse client JSON and convert to form data
            Console.WriteLine("\n[9/11] Preparing form data...");
            var formData = BuildFormDataFromJson(clientJson);
            Console.WriteLine($"  Form data fields prepared: {formData.Count()}");

            // 🔟 Create client with MULTIPART/FORM-DATA
            Console.WriteLine("\n[10/11] Creating client...");
            
            // Build cookie header
            string cookieHeader = cookieContainer.GetCookieHeader(new Uri(baseUrl));

            var createClientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            // Try with the UPDATED HTML token from create page
            Console.WriteLine($"  Using HTML CSRF token from create page (length: {htmlCsrfToken.Length})");
            createClientRequest.Headers.Add("X-CSRF-Token", htmlCsrfToken);
            createClientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            createClientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            createClientRequest.Headers.Add("Origin", baseUrl);
            createClientRequest.Headers.Add("Cookie", cookieHeader);

            Console.WriteLine($"  Sending POST to {baseUrl}/api/clients");

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

            // 1️⃣1️⃣ If failed, try cookie token as fallback
            if (!clientResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("\n[11/11] Retrying with cookie XSRF token...");
                
                var retryRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
                {
                    Content = formData
                };
                
                retryRequest.Headers.Add("X-CSRF-Token", cookieXsrfToken);
                retryRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
                retryRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
                retryRequest.Headers.Add("Origin", baseUrl);
                retryRequest.Headers.Add("Cookie", cookieHeader);
                
                var retryResponse = await client.SendAsync(retryRequest);
                var retryBody = await retryResponse.Content.ReadAsStringAsync();
                
                Console.WriteLine($"Retry Status: {retryResponse.StatusCode}");
                
                if (retryResponse.IsSuccessStatusCode)
                {
                    Console.WriteLine("\n✅✅✅ SUCCESS! Client created with cookie token ✅✅✅");
                    return;
                }
                else
                {
                    Console.WriteLine($"Retry Response: {retryBody}");
                    Console.WriteLine("\n❌ Both attempts failed");
                    Environment.Exit(1);
                }
            }
            else
            {
                Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ UNEXPECTED ERROR: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
            Environment.Exit(1);
        }
    }

    static MultipartFormDataContent BuildFormDataFromJson(string json)
    {
        var formData = new MultipartFormDataContent();
        
        try
        {
            var data = JsonSerializer.Deserialize<JsonElement>(json);
            
            // Helper to add form field
            void AddField(string name, string value)
            {
                formData.Add(new StringContent(value ?? ""), name);
            }

            // Process JSON recursively
            ProcessJsonElement(formData, data, "");
            
            return formData;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error building form data: {ex.Message}");
            throw;
        }
    }

    static void ProcessJsonElement(MultipartFormDataContent formData, JsonElement element, string prefix)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    string key = string.IsNullOrEmpty(prefix) 
                        ? property.Name 
                        : $"{prefix}[{property.Name}]";
                    ProcessJsonElement(formData, property.Value, key);
                }
                break;
                
            case JsonValueKind.Array:
                int index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object || item.ValueKind == JsonValueKind.Array)
                    {
                        ProcessJsonElement(formData, item, $"{prefix}[{index}]");
                    }
                    else
                    {
                        formData.Add(new StringContent(GetStringValue(item)), $"{prefix}[]");
                    }
                    index++;
                }
                
                // Handle empty arrays
                if (index == 0 && !string.IsNullOrEmpty(prefix))
                {
                    formData.Add(new StringContent(""), $"{prefix}[]");
                }
                break;
                
            default:
                formData.Add(new StringContent(GetStringValue(element)), prefix);
                break;
        }
    }

    static string GetStringValue(JsonElement element)
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
