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

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("Origin", baseUrl);
        client.DefaultRequestHeaders.Add("Referer", $"{baseUrl}/login");

        var loginPayload = new
        {
            email = username,
            password = password,
            totp_code = totp
        };
        var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");
        var loginResponse = await client.PostAsync($"{baseUrl}/api/login", loginContent);
        var loginBody = await loginResponse.Content.ReadAsStringAsync();

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed: {(int)loginResponse.StatusCode}");
            Console.WriteLine(loginBody);
            Environment.Exit(1);
        }
        Console.WriteLine("  ✓ Login successful");

        // 4️⃣ Refresh Sanctum CSRF cookie
        Console.WriteLine("[4/6] Refreshing Sanctum CSRF...");
        var sanctumResponse = await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
        sanctumResponse.EnsureSuccessStatusCode();
        Console.WriteLine("  ✓ Sanctum CSRF refreshed");

        // 5️⃣ Extract cookies
        Console.WriteLine("[5/6] Extracting cookies...");
        var cookies = cookieContainer.GetCookies(new Uri(baseUrl));
        string xsrf = null, session = null;

        foreach (Cookie c in cookies)
        {
            if (c.Name == "XSRF-TOKEN") xsrf = c.Value;
            if (c.Name == $"{tenant}_session") session = c.Value;
        }

        if (string.IsNullOrEmpty(xsrf) || string.IsNullOrEmpty(session))
        {
            Console.WriteLine("❌ Required cookies missing");
            Environment.Exit(1);
        }

        Console.WriteLine($"  ✓ Session cookie length: {session.Length}");
        Console.WriteLine($"  ✓ XSRF token length: {xsrf.Length}");

        // 6️⃣ Bind session to API (important for Sanctum)
        Console.WriteLine("[6/7] Binding session to API (/api/user)...");
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrf);
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Origin", baseUrl);
        client.DefaultRequestHeaders.Add("Referer", baseUrl);

        var userBind = await client.GetAsync($"{baseUrl}/api/user");
        userBind.EnsureSuccessStatusCode();
        Console.WriteLine("  ✓ API session bound");

        // 7️⃣ Create client
        Console.WriteLine("[7/7] Creating client...");
        var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
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
