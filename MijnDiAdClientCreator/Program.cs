using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

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

        Console.WriteLine("== MijnDiAd Auto-Login & Client Creation ==");

        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler 
        { 
            CookieContainer = cookieContainer, 
            UseCookies = true, 
            AutomaticDecompression = DecompressionMethods.All 
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        // 1️⃣ FETCH LOGIN PAGE
        Console.WriteLine("[1/5] Fetching login page...");
        var loginPageResponse = await client.GetAsync($"https://{tenant}.mijndiad.nl/login");
        loginPageResponse.EnsureSuccessStatusCode();
        var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // 2️⃣ EXTRACT CSRF TOKEN
        Console.WriteLine("[2/5] Extracting CSRF token...");
        var csrfMatch = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!csrfMatch.Success)
        {
            Console.WriteLine("❌ CSRF token not found");
            Environment.Exit(1);
        }
        var csrfToken = csrfMatch.Groups[1].Value;
        Console.WriteLine($"  ✓ CSRF token extracted");

        // 3️⃣ LOGIN
        Console.WriteLine("[3/5] Logging in...");
        Console.WriteLine($"  Generated TOTP: {totp}");
        
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/login");

        var loginPayload = new
        {
            email = username,
            password = password,
            totp_code = totp
        };
        var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");

        var loginResponse = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/login", loginContent);
        var loginBody = await loginResponse.Content.ReadAsStringAsync();
        
        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed: {(int)loginResponse.StatusCode}");
            Console.WriteLine(loginBody);
            Environment.Exit(1);
        }

        Console.WriteLine($"  ✓ Login successful");

        // 4️⃣ EXTRACT ALL SESSION COOKIES
        Console.WriteLine("[4/5] Extracting all session cookies...");
        var cookies = cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl"));
        string sessionCookie = null;
        string xsrfToken = null;
        var allCookies = new StringBuilder();
        
        foreach (Cookie cookie in cookies)
        {
            // Add all cookies to the cookie string IN THEIR ORIGINAL ENCODED FORM
            if (allCookies.Length > 0) allCookies.Append("; ");
            allCookies.Append($"{cookie.Name}={cookie.Value}");  // Keep URL-encoded!
            
            // Track specific important cookies
            if (cookie.Name == $"{tenant}_session")
            {
                sessionCookie = cookie.Value;
                Console.WriteLine($"  ✓ Session cookie: {sessionCookie.Substring(0, Math.Min(20, sessionCookie.Length))}... (length: {sessionCookie.Length})");
            }
            if (cookie.Name == "XSRF-TOKEN")
            {
                // Only decode for the header, not for the cookie string
                xsrfToken = Uri.UnescapeDataString(cookie.Value);
                Console.WriteLine($"  ✓ XSRF token: {xsrfToken.Substring(0, Math.Min(20, xsrfToken.Length))}... (length: {xsrfToken.Length})");
            }
            
            Console.WriteLine($"  ✓ Cookie: {cookie.Name} = {cookie.Value.Substring(0, Math.Min(20, cookie.Value.Length))}...");
        }
        
        var fullCookieHeader = allCookies.ToString();
        Console.WriteLine($"  Total cookies captured: {cookies.Count}");

        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
        {
            Console.WriteLine("❌ Session cookies not found");
            Environment.Exit(1);
        }

        // 4.5️⃣ VISIT DASHBOARD TO ESTABLISH SESSION
        Console.WriteLine("[4.5/5] Visiting dashboard to establish session...");
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml");
        
        var dashboardResponse = await client.GetAsync($"https://{tenant}.mijndiad.nl/dashboard");
        if (dashboardResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("  ✓ Dashboard loaded successfully");
            
            // Extract fresh XSRF token from dashboard page
            var dashboardHtml = await dashboardResponse.Content.ReadAsStringAsync();
            var dashboardCsrfMatch = Regex.Match(dashboardHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (dashboardCsrfMatch.Success)
            {
                xsrfToken = dashboardCsrfMatch.Groups[1].Value;
                Console.WriteLine($"  ✓ Refreshed XSRF token from dashboard (length: {xsrfToken.Length})");
            }
            
            // Refresh all cookies after dashboard visit
            cookies = cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl"));
            allCookies.Clear();
            
            foreach (Cookie cookie in cookies)
            {
                if (allCookies.Length > 0) allCookies.Append("; ");
                allCookies.Append($"{cookie.Name}={cookie.Value}");  // Keep URL-encoded!
            }
            
            fullCookieHeader = allCookies.ToString();
            Console.WriteLine($"  ✓ Refreshed all cookies (total: {cookies.Count})");
        }

        // 5️⃣ CREATE CLIENT
        Console.WriteLine("[5/5] Creating client...");
        
        // Create a completely new HttpClient without cookie container for this request
        using var apiClient = new HttpClient();
        var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"https://{tenant}.mijndiad.nl/api/clients");
        clientRequest.Content = new StringContent(clientJson, Encoding.UTF8, "application/json");
        
        // Add all required headers exactly as browser sends them
        clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
        clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
        clientRequest.Headers.Add("x-csrf-token", xsrfToken);
        clientRequest.Headers.Add("Origin", $"https://{tenant}.mijndiad.nl");
        clientRequest.Headers.Add("Referer", $"https://{tenant}.mijndiad.nl/clients/create");
        clientRequest.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        clientRequest.Headers.Add("Cookie", fullCookieHeader);
        
        Console.WriteLine($"  Posting to: https://{tenant}.mijndiad.nl/api/clients");
        Console.WriteLine($"  Full cookie header: {fullCookieHeader.Substring(0, Math.Min(100, fullCookieHeader.Length))}...");
        
        var clientResponse = await apiClient.SendAsync(clientRequest);
        var clientResponseBody = await clientResponse.Content.ReadAsStringAsync();

        Console.WriteLine($"\n== Response Status: {(int)clientResponse.StatusCode} ==");
        Console.WriteLine(clientResponseBody);

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

    static string GenerateTotp(string base32Secret)
    {
        if (string.IsNullOrEmpty(base32Secret)) return "000000";
        
        var key = Base32Decode(base32Secret);
        var timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var data = BitConverter.GetBytes(timestep);
        if (BitConverter.IsLittleEndian) Array.Reverse(data);
        
        using var hmac = new System.Security.Cryptography.HMACSHA1(key);
        var hash = hmac.ComputeHash(data);
        
        int offset = hash[^1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);
        
        return (binary % 1_000_000).ToString("D6");
    }

    static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new byte[input.Length * 5 / 8];
        int bitBuffer = 0, bitCount = 0, index = 0;

        foreach (char c in input.TrimEnd('='))
        {
            int charIndex = alphabet.IndexOf(c);
            if (charIndex < 0) continue;
            
            bitBuffer = (bitBuffer << 5) | charIndex;
            bitCount += 5;

            if (bitCount >= 8)
            {
                output[index++] = (byte)(bitBuffer >> (bitCount - 8));
                bitCount -= 8;
            }
        }

        Array.Resize(ref output, index);
        return output;
    }
}
