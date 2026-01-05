using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
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
            AllowAutoRedirect = true
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");

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
            
            // Clear any existing headers and set login headers
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

            // 5️⃣ Extract cookies
            Console.WriteLine("\n[5/8] Extracting cookies...");
            var cookies = cookieContainer.GetCookies(new Uri(baseUrl));
            
            string? xsrfToken = null;
            string? sessionCookie = null;
            string? deviceToken = null;
            string? mdsbCookie = null;

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
                else if (c.Name == "mdsb")
                {
                    mdsbCookie = c.Value;
                }
            }

            if (string.IsNullOrEmpty(xsrfToken) || string.IsNullOrEmpty(sessionCookie))
            {
                Console.WriteLine("❌ Required cookies missing");
                Console.WriteLine($"XSRF-TOKEN: {!string.IsNullOrEmpty(xsrfToken)}");
                Console.WriteLine($"Session: {!string.IsNullOrEmpty(sessionCookie)}");
                Environment.Exit(1);
            }

            Console.WriteLine($"  ✓ All cookies extracted");

            // 6️⃣ Verify session with API user endpoint
            Console.WriteLine("\n[6/8] Verifying authenticated session...");
            
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
            
            // Parse user response to confirm we're authenticated
            try
            {
                var userJson = JsonSerializer.Deserialize<JsonElement>(userBody);
                if (userJson.TryGetProperty("email", out var email))
                {
                    Console.WriteLine($"  ✓ Authenticated as: {email}");
                }
                else
                {
                    Console.WriteLine($"  ✓ Session verified");
                }
            }
            catch
            {
                Console.WriteLine($"  ✓ Session verified (raw response)");
            }

            // 7️⃣ Optional: Navigate to clients page first to establish context
            Console.WriteLine("\n[7/8] Loading clients page context...");
            var clientsPageRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/clients");
            clientsPageRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
            clientsPageRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientsPageRequest.Headers.Add("Referer", $"{baseUrl}/");
            
            var clientsPageResponse = await client.SendAsync(clientsPageRequest);
            Console.WriteLine($"  Clients page: {clientsPageResponse.StatusCode}");
            
            if (clientsPageResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("  ✓ Clients context loaded");
            }

            // 8️⃣ Create client
            Console.WriteLine("\n[8/8] Creating client...");
            
            // Log the JSON payload for debugging
            Console.WriteLine($"  Payload length: {clientJson.Length} chars");
            
            var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
            
            var createClientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = clientContent
            };
            
            // Add ALL required headers
            createClientRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
            createClientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            createClientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            createClientRequest.Headers.Add("Origin", baseUrl);
            
            // Add device token if available
            if (!string.IsNullOrEmpty(deviceToken))
            {
                createClientRequest.Headers.Add("X-Device-Token", deviceToken);
            }
            
            Console.WriteLine("  Sending request with headers:");
            Console.WriteLine($"    X-XSRF-TOKEN: {xsrfToken.Length} chars");
            Console.WriteLine($"    X-Requested-With: XMLHttpRequest");
            Console.WriteLine($"    Referer: {baseUrl}/clients/create");
            
            var clientResponse = await client.SendAsync(createClientRequest);
            var clientResponseBody = await clientResponse.Content.ReadAsStringAsync();

            Console.WriteLine($"\n=== CLIENT CREATION RESPONSE ===");
            Console.WriteLine($"Status: {(int)clientResponse.StatusCode} ({clientResponse.StatusCode})");
            Console.WriteLine($"Response length: {clientResponseBody.Length} chars");
            
            if (!string.IsNullOrEmpty(clientResponseBody))
            {
                try
                {
                    var json = JsonSerializer.Deserialize<JsonElement>(clientResponseBody);
                    var formatted = JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true });
                    Console.WriteLine($"Response body:\n{formatted}");
                }
                catch (JsonException)
                {
                    Console.WriteLine($"Response body (not JSON):\n{clientResponseBody}");
                }
            }

            if (!clientResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("\n❌ Client creation failed");
                
                // Additional debugging
                Console.WriteLine("\n=== COOKIE DEBUG INFO ===");
                foreach (Cookie c in cookies)
                {
                    Console.WriteLine($"{c.Name}: {c.Value.Length} chars, Domain: {c.Domain}, Path: {c.Path}, Secure: {c.Secure}, HttpOnly: {c.HttpOnly}");
                }
                
                Environment.Exit(1);
            }

            Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
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
