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

        // 4️⃣ EXTRACT SESSION COOKIES
        Console.WriteLine("[4/5] Extracting session cookies...");
        var cookies = cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl"));
        string sessionCookie = null;
        string xsrfToken = null;
        
        foreach (Cookie cookie in cookies)
        {
            if (cookie.Name == $"{tenant}_session")
            {
                sessionCookie = cookie.Value;
                Console.WriteLine($"  ✓ Session cookie: {sessionCookie.Substring(0, 20)}...");
            }
            if (cookie.Name == "XSRF-TOKEN")
            {
                xsrfToken = cookie.Value;
                Console.WriteLine($"  ✓ XSRF token: {xsrfToken.Substring(0, 20)}...");
            }
        }

        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
        {
            Console.WriteLine("❌ Session cookies not found");
            Environment.Exit(1);
        }

        // 5️⃣ CREATE CLIENT
        Console.WriteLine("[5/5] Creating client...");
        
        // Create a new request with explicit cookie header
        var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"https://{tenant}.mijndiad.nl/api/clients");
        clientRequest.Content = new StringContent(clientJson, Encoding.UTF8, "application/json");
        
        // Add all required headers
        clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
        clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
        clientRequest.Headers.Add("X-CSRF-TOKEN", xsrfToken);
        clientRequest.Headers.Add("Origin", $"https://{tenant}.mijndiad.nl");
        clientRequest.Headers.Add("Referer", $"https://{tenant}.mijndiad.nl/clients/create");
        clientRequest.Headers.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");
        
        Console.WriteLine($"  Posting to: https://{tenant}.mijndiad.nl/api/clients");
        Console.WriteLine($"  With cookies: {tenant}_session and XSRF-TOKEN");
        
        var clientResponse = await client.SendAsync(clientRequest);
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
