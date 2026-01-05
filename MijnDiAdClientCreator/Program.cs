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
        if (args.Length < 2 || args[0] != "--json")
        {
            Console.WriteLine("Usage: dotnet run -- --json '{\"firstname\":\"John\", ...}'");
            return;
        }

        string clientJson = args[1];

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? throw new Exception("MIJNDIAD_TENANT not set");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") ?? throw new Exception("MIJNDIAD_USERNAME not set");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") ?? throw new Exception("MIJNDIAD_PASSWORD not set");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") ?? throw new Exception("MIJNDIAD_TOTP_SECRET not set");
        var totp = GenerateTotp(totpSecret);

        var baseUrl = $"https://{tenant}.mijndiad.nl";

        Console.WriteLine("== MijnDiAd Auto-Login & Client Creation ==");
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

            // 5️⃣ Add locale cookie (IMPORTANT: based on browser request)
            Console.WriteLine("\n[5/8] Setting locale cookie...");
            cookieContainer.Add(new Uri(baseUrl), new Cookie("locale", "nl"));
            Console.WriteLine("  ✓ Locale cookie set to 'nl'");

            // 6️⃣ Verify session with API user endpoint
            Console.WriteLine("\n[6/8] Verifying authenticated session...");
            
            // Get plain XSRF token from cookies (not URL-decoded)
            string plainXsrfToken = null;
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
            userRequest.Headers.Add("X-CSRF-Token", plainXsrfToken); // Note: X-CSRF-Token, not X-XSRF-TOKEN
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
            var formData = new MultipartFormDataContent();
            
            try
            {
                var clientData = JsonSerializer.Deserialize<JsonElement>(clientJson);
                AddJsonToFormData(formData, clientData, "");
                
                // Debug: Show form data fields
                Console.WriteLine($"  Form data fields prepared: {formData.Count()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error parsing JSON: {ex.Message}");
                Environment.Exit(1);
            }

            // 8️⃣ Create client with MULTIPART/FORM-DATA
            Console.WriteLine("\n[8/8] Creating client...");
            
            // Build cookie header manually to ensure all cookies are included
            string cookieHeader = cookieContainer.GetCookieHeader(new Uri(baseUrl));
            Console.WriteLine($"  Cookie header length: {cookieHeader.Length} chars");

            var createClientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            // CRITICAL HEADERS - match browser exactly
            createClientRequest.Headers.Add("X-CSRF-Token", plainXsrfToken); // X-CSRF-Token, not X-XSRF-TOKEN
            createClientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            createClientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            createClientRequest.Headers.Add("Origin", baseUrl);
            createClientRequest.Headers.Add("Cookie", cookieHeader);
            createClientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            createClientRequest.Headers.Add("Accept-Language", "nl");
            createClientRequest.Headers.Add("Accept-Encoding", "gzip, deflate, br, zstd");
            createClientRequest.Headers.Add("Sec-Ch-Ua", "\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"");
            createClientRequest.Headers.Add("Sec-Ch-Ua-Mobile", "?0");
            createClientRequest.Headers.Add("Sec-Ch-Ua-Platform", "\"Windows\"");
            createClientRequest.Headers.Add("Sec-Fetch-Dest", "empty");
            createClientRequest.Headers.Add("Sec-Fetch-Mode", "cors");
            createClientRequest.Headers.Add("Sec-Fetch-Site", "same-origin");
            createClientRequest.Headers.Add("Priority", "u=1, i");

            Console.WriteLine("  Sending request with multipart/form-data...");

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

    // Helper method to recursively add JSON data to form data
    static void AddJsonToFormData(MultipartFormDataContent formData, JsonElement element, string prefix)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    string key = string.IsNullOrEmpty(prefix) 
                        ? property.Name 
                        : $"{prefix}[{property.Name}]";
                    AddJsonToFormData(formData, property.Value, key);
                }
                break;
                
            case JsonValueKind.Array:
                int index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object || item.ValueKind == JsonValueKind.Array)
                    {
                        AddJsonToFormData(formData, item, $"{prefix}[{index}]");
                    }
                    else
                    {
                        // For simple arrays, use empty brackets
                        formData.Add(new StringContent(GetStringValue(item)), $"{prefix}[]");
                    }
                    index++;
                }
                
                // Handle empty arrays - add empty field
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

    // Helper to convert JsonElement to string
    static string GetStringValue(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "1",
            JsonValueKind.False => "0",
            JsonValueKind.Null => "",
            _ => element.ToString()
        };
    }

    // TOTP generation using OtpNET
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
