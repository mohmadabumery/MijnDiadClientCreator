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
        client.DefaultRequestHeaders.Add("User-Agent", "MijnDiAdClientCreator/1.0");

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
        loginContent.Headers.Clear();
        loginContent.Headers.Add("Content-Type", "application/json");
        loginContent.Headers.Add("Accept", "application/json");
        loginContent.Headers.Add("X-CSRF-TOKEN", csrfToken);
        loginContent.Headers.Add("X-Requested-With", "XMLHttpRequest");
        
        var loginResponse = await client.PostAsync($"{baseUrl}/api/login", loginContent);
        var loginBody = await loginResponse.Content.ReadAsStringAsync();

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed: {(int)loginResponse.StatusCode}");
            Console.WriteLine(loginBody);
            Environment.Exit(1);
        }
        Console.WriteLine("  ✓ Login successful");

        // 4️⃣ Get Sanctum CSRF cookie (crucial for Laravel Sanctum)
        Console.WriteLine("[4/6] Getting Sanctum CSRF cookie...");
        var sanctumResponse = await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
        sanctumResponse.EnsureSuccessStatusCode();
        Console.WriteLine("  ✓ Sanctum CSRF cookie set");

        // 5️⃣ Extract cookies
        Console.WriteLine("[5/6] Extracting cookies...");
        var cookies = cookieContainer.GetCookies(new Uri(baseUrl));
        string xsrfToken = null, sessionCookie = null;

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
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
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
        clientContent.Headers.Clear();
        clientContent.Headers.Add("Content-Type", "application/json");
        clientContent.Headers.Add("X-XSRF-TOKEN", xsrfToken);
        clientContent.Headers.Add("X-Requested-With", "XMLHttpRequest");
        clientContent.Headers.Add("Referer", $"{baseUrl}/clients/create");
        
        var clientResponse = await client.PostAsync($"{baseUrl}/api/clients", clientContent);
        var clientResponseBody = await clientResponse.Content.ReadAsStringAsync();

        Console.WriteLine($"\n== Response Status: {(int)clientResponse.StatusCode} ==");
        Console.WriteLine(clientResponseBody);

        if (!clientResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("\n❌ Client creation failed");
            Environment.Exit(1);
        }

        Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
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
