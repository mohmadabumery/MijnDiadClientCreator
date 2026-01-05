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
            Console.WriteLine("Usage: dotnet run -- --json '{\"firstname\":\"John\"}'");
            return;
        }

        string clientJson = args[1];

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? throw new Exception("MIJNDIAD_TENANT not set");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") ?? throw new Exception("MIJNDIAD_USERNAME not set");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") ?? throw new Exception("MIJNDIAD_PASSWORD not set");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") ?? throw new Exception("MIJNDIAD_TOTP_SECRET not set");

        var totp = GenerateTotp(totpSecret);

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
        Console.WriteLine("[1/5] Fetching login page...");
        var loginPageResponse = await client.GetAsync($"https://{tenant}.mijndiad.nl/login");
        loginPageResponse.EnsureSuccessStatusCode();
        var loginHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // 2️⃣ Extract CSRF token
        Console.WriteLine("[2/5] Extracting CSRF token...");
        var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!csrfMatch.Success)
            throw new Exception("CSRF token not found");

        var csrfToken = csrfMatch.Groups[1].Value;
        Console.WriteLine("  ✓ CSRF token extracted");

        // 3️⃣ Login
        Console.WriteLine("[3/5] Logging in...");
        Console.WriteLine($"  Generated TOTP: {totp}");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
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

        var loginResponse = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/login",
            new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json")
        );

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine(await loginResponse.Content.ReadAsStringAsync());
            throw new Exception("Login failed");
        }

        Console.WriteLine("  ✓ Login successful");

        // 4️⃣ Extract cookies
        Console.WriteLine("[4/5] Extracting session cookies...");
        var cookies = cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl"));

        string? sessionCookie = null;
        string? xsrfToken = null;

        foreach (Cookie cookie in cookies)
        {
            Console.WriteLine($"  Cookie: {cookie.Name}");

            if (cookie.Name == $"{tenant}_session")
                sessionCookie = cookie.Value;

            if (cookie.Name == "XSRF-TOKEN")
                xsrfToken = Uri.UnescapeDataString(cookie.Value); // 🔥 CRITICAL FIX
        }

        if (sessionCookie == null || xsrfToken == null)
            throw new Exception("Required session cookies missing");

        Console.WriteLine($"  ✓ Session cookie length: {sessionCookie.Length}");
        Console.WriteLine($"  ✓ XSRF token length: {xsrfToken.Length}");

        // 5️⃣ Create client
        Console.WriteLine("[5/5] Creating client...");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrfToken); // 🔥 CORRECT HEADER
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/clients/create");

        var createResponse = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/clients",
            new StringContent(clientJson, Encoding.UTF8, "application/json")
        );

        var responseBody = await createResponse.Content.ReadAsStringAsync();

        Console.WriteLine($"\n== Response Status: {(int)createResponse.StatusCode} ==");
        Console.WriteLine(responseBody);

        if (!createResponse.IsSuccessStatusCode)
            throw new Exception("Client creation failed");

        Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
    }

    static string GenerateTotp(string base32Secret)
    {
        var key = Base32Decode(base32Secret);
        var timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var data = BitConverter.GetBytes(timestep);
        if (BitConverter.IsLittleEndian) Array.Reverse(data);

        using var hmac = new System.Security.Cryptography.HMACSHA1(key);
        var hash = hmac.ComputeHash(data);

        int offset = hash[^1] & 0x0F;
        int binary =
            ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);

        return (binary % 1_000_000).ToString("D6");
    }

    static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new byte[input.Length * 5 / 8];
        int buffer = 0, bits = 0, index = 0;

        foreach (char c in input.TrimEnd('='))
        {
            int val = alphabet.IndexOf(c);
            if (val < 0) continue;

            buffer = (buffer << 5) | val;
            bits += 5;

            if (bits >= 8)
            {
                output[index++] = (byte)(buffer >> (bits - 8));
                bits -= 8;
            }
        }

        Array.Resize(ref output, index);
        return output;
    }
}
