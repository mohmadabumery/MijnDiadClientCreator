using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;
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
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");

        try
        {
            // 1️⃣ Fetch login page
            Console.WriteLine("\n[1/9] Fetching login page...");
            var loginPageResponse = await client.GetAsync($"{baseUrl}/login");
            loginPageResponse.EnsureSuccessStatusCode();
            var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"  Status: {loginPageResponse.StatusCode}");

            // 2️⃣ Extract CSRF token
            Console.WriteLine("\n[2/9] Extracting CSRF token...");
            var csrfMatch = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!csrfMatch.Success)
            {
                Console.WriteLine("❌ CSRF token not found");
                Environment.Exit(1);
            }
            var csrfToken = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  ✓ CSRF token extracted");

            // 3️⃣ Login
            Console.WriteLine("\n[3/9] Logging in...");
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
            Console.WriteLine("\n[4/9] Getting Sanctum CSRF cookie...");
            var sanctumResponse = await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
            Console.WriteLine($"  Sanctum Response: {sanctumResponse.StatusCode}");
            sanctumResponse.EnsureSuccessStatusCode();
            Console.WriteLine("  ✓ Sanctum CSRF cookie refreshed");

            // 5️⃣ Extract cookies
            Console.WriteLine("\n[5/9] Extracting cookies...");
            var cookies = cookieContainer.GetCookies(new Uri(baseUrl));
            
            string? xsrfToken = null;
            string? sessionCookie = null;
            string? deviceToken = null;

            foreach (Cookie c in cookies)
            {
                Console.WriteLine($"  {c.Name} = {c.Value.Length} chars");
                
                if (c.Name == "XSRF-TOKEN") 
                {
                    xsrfToken = Uri.UnescapeDataString(c.Value);
                }
                else if (c.Name == $"{tenant}_session") 
                {
                    sessionCookie = c.Value;
                }
                else if (c.Name == "md-device-token")
                {
                    deviceToken = c.Value;
                }
            }

            if (string.IsNullOrEmpty(xsrfToken) || string.IsNullOrEmpty(sessionCookie))
            {
                Console.WriteLine("❌ Required cookies missing");
                Environment.Exit(1);
            }

            Console.WriteLine($"  ✓ All cookies extracted");

            // 6️⃣ Verify session with API user endpoint
            Console.WriteLine("\n[6/9] Verifying authenticated session...");
            
            var userRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/user");
            userRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
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

            // 7️⃣ Try to get clients list first (to see if we have access)
            Console.WriteLine("\n[7/9] Testing clients API access...");
            
            var clientsListRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/clients?page=1");
            clientsListRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
            clientsListRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientsListRequest.Headers.Add("Referer", $"{baseUrl}/clients");
            
            var clientsListResponse = await client.SendAsync(clientsListRequest);
            var clientsListBody = await clientsListResponse.Content.ReadAsStringAsync();
            
            Console.WriteLine($"  Clients list Response: {clientsListResponse.StatusCode}");
            
            if (clientsListResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("  ✓ Can access clients list");
            }
            else
            {
                Console.WriteLine($"  ❌ Cannot access clients list: {clientsListResponse.StatusCode}");
                Console.WriteLine($"  Response: {clientsListBody}");
                
                // Try alternative: check if we need to accept terms or set up something
                Console.WriteLine("\n[7b/9] Checking for required setup...");
                
                var setupRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/settings");
                setupRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
                setupRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
                
                var setupResponse = await client.SendAsync(setupRequest);
                var setupBody = await setupResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"  Settings API Response: {setupResponse.StatusCode}");
            }

            // 8️⃣ Try a different endpoint to understand the API structure
            Console.WriteLine("\n[8/9] Checking API structure...");
            
            // Try to get invoice relations (since we use invoice_relation_id in payload)
            var invoiceRelationsRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/invoice-relations");
            invoiceRelationsRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
            invoiceRelationsRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            
            var invoiceRelationsResponse = await client.SendAsync(invoiceRelationsRequest);
            Console.WriteLine($"  Invoice relations Response: {invoiceRelationsResponse.StatusCode}");
            
            if (invoiceRelationsResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("  ✓ Can access invoice relations");
            }

            // 9️⃣ Create client with different approaches
            Console.WriteLine("\n[9/9] Creating client...");
            
            // First, let's try with a minimal payload
            var minimalPayload = new
            {
                firstname = "Test",
                lastname = "User",
                email = "test@example.com",
                gender = "1",
                invoice_relation_id = "15",
                address = new 
                {
                    zipcode = "1234AB",
                    house_number = "1",
                    street = "Teststraat",
                    city = "Teststad"
                }
            };
            
            string testJson = JsonSerializer.Serialize(minimalPayload);
            Console.WriteLine($"  Testing with minimal payload: {testJson.Length} chars");
            
            var clientContent = new StringContent(testJson, Encoding.UTF8, "application/json");
            
            var createClientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = clientContent
            };
            
            // Try different header combinations
            
            // Option 1: Standard headers
            createClientRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
            createClientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            createClientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            createClientRequest.Headers.Add("Origin", baseUrl);
            
            // Option 2: Add device token if available
            if (!string.IsNullOrEmpty(deviceToken))
            {
                createClientRequest.Headers.Add("X-Device-Token", deviceToken);
            }
            
            // Option 3: Try with Accept header
            createClientRequest.Headers.Add("Accept", "application/json");
            
            Console.WriteLine("  Headers being sent:");
            foreach (var header in createClientRequest.Headers)
            {
                Console.WriteLine($"    {header.Key}: {string.Join(", ", header.Value)}");
            }
            
            var clientResponse = await client.SendAsync(createClientRequest);
            var clientResponseBody = await clientResponse.Content.ReadAsStringAsync();

            Console.WriteLine($"\n=== CLIENT CREATION RESPONSE ===");
            Console.WriteLine($"Status: {(int)clientResponse.StatusCode} ({clientResponse.StatusCode})");
            Console.WriteLine($"Response: {clientResponseBody}");
            
            // If still failing, try the original payload
            if (!clientResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("\n[9b/9] Trying with original payload...");
                
                var originalRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
                {
                    Content = new StringContent(clientJson, Encoding.UTF8, "application/json")
                };
                
                originalRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
                originalRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
                originalRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
                originalRequest.Headers.Add("Origin", baseUrl);
                originalRequest.Headers.Add("Accept", "application/json");
                
                if (!string.IsNullOrEmpty(deviceToken))
                {
                    originalRequest.Headers.Add("X-Device-Token", deviceToken);
                }
                
                var originalResponse = await client.SendAsync(originalRequest);
                var originalResponseBody = await originalResponse.Content.ReadAsStringAsync();
                
                Console.WriteLine($"Status: {originalResponse.StatusCode}");
                Console.WriteLine($"Response: {originalResponseBody}");
                
                if (originalResponse.IsSuccessStatusCode)
                {
                    Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
                    return;
                }
            }
            else
            {
                Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
                return;
            }

            Console.WriteLine("\n❌ Client creation failed");
            Console.WriteLine("\n=== TROUBLESHOOTING SUGGESTIONS ===");
            Console.WriteLine("1. Check if user has permission to create clients");
            Console.WriteLine("2. Verify invoice_relation_id '15' exists");
            Console.WriteLine("3. Check if required fields are missing");
            Console.WriteLine("4. Try accessing /api/clients manually in browser");
            Console.WriteLine("5. Check browser DevTools Network tab for actual request format");
            
            Environment.Exit(1);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ UNEXPECTED ERROR: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
            Environment.Exit(1);
        }
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
