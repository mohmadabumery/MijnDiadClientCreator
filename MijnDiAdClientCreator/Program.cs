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

        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");

        // 1️⃣ Fetch login page
        Console.WriteLine("[1/6] Fetching login page...");
        var loginPageResponse = await client.GetAsync($"{baseUrl}/login");
        loginPageResponse.EnsureSuccessStatusCode();
        var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // 2️⃣ Extract CSRF token
        Console.WriteLine("[2/6] Extracting CSRF token...");
        var csrfMatch = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!csrfMatch.Success)
        {
            Console.WriteLine("❌ CSRF token not found");
            Environment.Exit(1);
        }
        var csrfToken = csrfMatch.Groups[1].Value;
        Console.WriteLine("  ✓ CSRF token extracted");

        // 3️⃣ Login
        Console.WriteLine("[3/6] Logging in...");
        Console.WriteLine($"  Generated TOTP: {totp}");

        var loginPayload = new
        {
            email = username,
            password = password,
            totp_code = totp
        };
        
        var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");
        
        // Clear headers and set new ones for login
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Remove("X-Requested-With");
        client.DefaultRequestHeaders.Remove("Origin");
        client.DefaultRequestHeaders.Remove("Referer");
        
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Origin", baseUrl);
        client.DefaultRequestHeaders.Add("Referer", $"{baseUrl}/login");
        
        var loginResponse = await client.PostAsync($"{baseUrl}/api/login", loginContent);
        var loginBody = await loginResponse.Content.ReadAsStringAsync();

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed: {(int)loginResponse.StatusCode}");
            Console.WriteLine(loginBody);
            Environment.Exit(1);
        }
        Console.WriteLine("  ✓ Login successful");

        // 4️⃣ Get Sanctum CSRF cookie
        Console.WriteLine("[4/6] Getting Sanctum CSRF cookie...");
        
        // Clear headers for sanctum request
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Remove("X-Requested-With");
        client.DefaultRequestHeaders.Remove("Origin");
        client.DefaultRequestHeaders.Remove("Referer");
        
        var sanctumResponse = await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
        sanctumResponse.EnsureSuccessStatusCode();
        Console.WriteLine("  ✓ Sanctum CSRF cookie set");

        // 5️⃣ Extract cookies
        Console.WriteLine("[5/6] Extracting cookies...");
        var cookies = cookieContainer.GetCookies(new Uri(baseUrl));
        string? xsrfToken = null;
        string? sessionCookie = null;

        foreach (Cookie c in cookies)
        {
            if (c.Name == "XSRF-TOKEN") xsrfToken = Uri.UnescapeDataString(c.Value);
            if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
        }

        if (string.IsNullOrEmpty(xsrfToken) || string.IsNullOrEmpty(sessionCookie))
        {
            Console.WriteLine("❌ Required cookies missing");
            Console.WriteLine($"XSRF-TOKEN: {xsrfToken?.Length ?? 0} chars");
            Console.WriteLine($"Session: {sessionCookie?.Length ?? 0} chars");
            Environment.Exit(1);
        }

        Console.WriteLine($"  ✓ Session cookie: {sessionCookie.Length} chars");
        Console.WriteLine($"  ✓ XSRF token: {xsrfToken.Length} chars");

        // 6️⃣ Bind session to API by fetching user info
        Console.WriteLine("[6/7] Verifying authenticated session...");
        
        // Set headers for API request
        client.DefaultRequestHeaders.Remove("X-XSRF-TOKEN");
        client.DefaultRequestHeaders.Remove("Referer");
        
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrfToken);
        client.DefaultRequestHeaders.Add("Referer", $"{baseUrl}/");
        
        var userResponse = await client.GetAsync($"{baseUrl}/api/user");
        var userBody = await userResponse.Content.ReadAsStringAsync();
        
        if (!userResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Session verification failed: {(int)userResponse.StatusCode}");
            Console.WriteLine(userBody);
            Environment.Exit(1);
        }
        Console.WriteLine("  ✓ Session verified and bound");

        // 7️⃣ Create client with proper headers
        Console.WriteLine("[7/7] Creating client...");
        
        var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
        
        // Update headers for client creation
        client.DefaultRequestHeaders.Remove("Referer");
        client.DefaultRequestHeaders.Add("Referer", $"{baseUrl}/clients/create");
        
        var clientResponse = await client.PostAsync($"{baseUrl}/api/clients", clientContent);
        var clientResponseBody = await clientResponse.Content.ReadAsStringAsync();

        Console.WriteLine($"\n== Response Status: {(int)clientResponse.StatusCode} ==");
        Console.WriteLine(clientResponseBody);

        if (!clientResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("\n❌ Client creation failed");
            
            // Try to parse error message
            try
            {
                var errorObj = JsonSerializer.Deserialize<JsonElement>(clientResponseBody);
                if (errorObj.TryGetProperty("messages", out var messages))
                {
                    Console.WriteLine("Error messages:");
                    foreach (var msg in messages.EnumerateArray())
                    {
                        Console.WriteLine($"  - {msg}");
                    }
                }
            }
            catch
            {
                // If we can't parse JSON, just show raw response
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
            return "123456"; // Fallback for testing
        }
    }
}
