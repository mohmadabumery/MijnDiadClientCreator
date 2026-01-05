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

        // Configure HttpClient with cookies
        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            UseDefaultCredentials = false,
            AutomaticDecompression = DecompressionMethods.All,
            AllowAutoRedirect = false // Important: don't auto-redirect
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");

        // 1️⃣ Fetch login page
        Console.WriteLine("[1/7] Fetching login page...");
        var loginPageResponse = await client.GetAsync($"{baseUrl}/login");
        loginPageResponse.EnsureSuccessStatusCode();
        var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // 2️⃣ Extract CSRF token
        Console.WriteLine("[2/7] Extracting CSRF token...");
        var csrfMatch = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!csrfMatch.Success)
        {
            Console.WriteLine("❌ CSRF token not found");
            Environment.Exit(1);
        }
        var csrfToken = csrfMatch.Groups[1].Value;
        Console.WriteLine($"  ✓ CSRF token extracted: {csrfToken.Substring(0, Math.Min(20, csrfToken.Length))}...");

        // 3️⃣ Login
        Console.WriteLine("[3/7] Logging in...");
        Console.WriteLine($"  Generated TOTP: {totp}");

        var loginPayload = new
        {
            email = username,
            password = password,
            totp_code = totp
        };
        
        var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");
        
        // Create a new HttpRequestMessage for login to control headers precisely
        var loginRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/login");
        loginRequest.Content = loginContent;
        loginRequest.Headers.Add("X-CSRF-TOKEN", csrfToken);
        loginRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
        loginRequest.Headers.Add("Origin", baseUrl);
        loginRequest.Headers.Add("Referer", $"{baseUrl}/login");
        
        var loginResponse = await client.SendAsync(loginRequest);
        var loginBody = await loginResponse.Content.ReadAsStringAsync();

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed: {(int)loginResponse.StatusCode}");
            Console.WriteLine(loginBody);
            Environment.Exit(1);
        }
        Console.WriteLine("  ✓ Login successful");

        // 4️⃣ Get Sanctum CSRF cookie (IMPORTANT: must be done after login)
        Console.WriteLine("[4/7] Getting Sanctum CSRF cookie...");
        
        // Clear default headers and set fresh ones
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
        
        var sanctumResponse = await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
        sanctumResponse.EnsureSuccessStatusCode();
        Console.WriteLine("  ✓ Sanctum CSRF cookie set");

        // 5️⃣ Extract and decode cookies
        Console.WriteLine("[5/7] Extracting cookies...");
        var cookies = cookieContainer.GetCookies(new Uri(baseUrl));
        string? xsrfToken = null;
        string? sessionCookie = null;

        foreach (Cookie c in cookies)
        {
            Console.WriteLine($"  Cookie: {c.Name} = {c.Value.Length} chars");
            if (c.Name == "XSRF-TOKEN") 
            {
                xsrfToken = Uri.UnescapeDataString(c.Value);
                Console.WriteLine($"    XSRF decoded length: {xsrfToken.Length}");
            }
            if (c.Name == $"{tenant}_session") 
            {
                sessionCookie = c.Value;
            }
        }

        if (string.IsNullOrEmpty(xsrfToken) || string.IsNullOrEmpty(sessionCookie))
        {
            Console.WriteLine("❌ Required cookies missing");
            Console.WriteLine($"XSRF-TOKEN present: {!string.IsNullOrEmpty(xsrfToken)}");
            Console.WriteLine($"Session cookie present: {!string.IsNullOrEmpty(sessionCookie)}");
            Environment.Exit(1);
        }

        Console.WriteLine($"  ✓ Session cookie: {sessionCookie.Length} chars");
        Console.WriteLine($"  ✓ XSRF token: {xsrfToken.Length} chars");

        // 6️⃣ Verify session with API user endpoint
        Console.WriteLine("[6/7] Verifying authenticated session...");
        
        // Create a request with proper headers
        var userRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/user");
        userRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
        userRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
        userRequest.Headers.Add("Referer", $"{baseUrl}/");
        
        var userResponse = await client.SendAsync(userRequest);
        var userBody = await userResponse.Content.ReadAsStringAsync();
        
        if (!userResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Session verification failed: {(int)userResponse.StatusCode}");
            Console.WriteLine(userBody);
            Environment.Exit(1);
        }
        Console.WriteLine("  ✓ Session verified and bound");

        // 7️⃣ Create client
        Console.WriteLine("[7/7] Creating client...");
        
        var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
        
        // Create client creation request
        var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients");
        clientRequest.Content = clientContent;
        clientRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
        clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
        clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
        
        var clientResponse = await client.SendAsync(clientRequest);
        var clientResponseBody = await clientResponse.Content.ReadAsStringAsync();

        Console.WriteLine($"\n== Response Status: {(int)clientResponse.StatusCode} ==");
        
        // Try to parse the response
        try
        {
            if (!string.IsNullOrEmpty(clientResponseBody))
            {
                var json = JsonSerializer.Deserialize<JsonElement>(clientResponseBody);
                var formatted = JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true });
                Console.WriteLine(formatted);
            }
            else
            {
                Console.WriteLine(clientResponseBody);
            }
        }
        catch
        {
            Console.WriteLine(clientResponseBody);
        }

        if (!clientResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("\n❌ Client creation failed");
            
            // Additional debugging info
            Console.WriteLine("\n=== Debug Info ===");
            Console.WriteLine($"XSRF Token length: {xsrfToken.Length}");
            Console.WriteLine($"Session cookie length: {sessionCookie.Length}");
            Console.WriteLine($"Request URL: {baseUrl}/api/clients");
            
            // Check if there are validation errors
            if (clientResponse.StatusCode == System.Net.HttpStatusCode.UnprocessableEntity)
            {
                Console.WriteLine("Validation errors detected");
            }
            
            Environment.Exit(1);
        }

        Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
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
