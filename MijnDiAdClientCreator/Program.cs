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
            throw new Exception("Usage: --json '{...}'");

        string clientJson = args[1];

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT")!;
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME")!;
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD")!;
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET")!;

        var baseUrl = $"https://{tenant}.mijndiad.nl";

        Console.WriteLine("== MijnDiAd Auto-Login & Client Creation ==");
        Console.WriteLine($"Running on: {Environment.MachineName}");

        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookies,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler)
        {
            BaseAddress = new Uri(baseUrl)
        };

        // 1️⃣ Fetch login page
        Console.WriteLine("[1/6] Fetching login page...");
        var loginHtml = await client.GetStringAsync("/login");

        // 2️⃣ Extract CSRF
        Console.WriteLine("[2/6] Extracting CSRF token...");
        var csrf = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"")
                        .Groups[1].Value;

        // 3️⃣ Login
        Console.WriteLine("[3/6] Logging in...");
        var totp = GenerateTotp(totpSecret);

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrf);
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Origin", baseUrl);
        client.DefaultRequestHeaders.Add("Referer", $"{baseUrl}/login");

        var loginResponse = await client.PostAsync(
            "/api/login",
            new StringContent(JsonSerializer.Serialize(new
            {
                email = username,
                password = password,
                totp_code = totp
            }), Encoding.UTF8, "application/json")
        );

        loginResponse.EnsureSuccessStatusCode();
        Console.WriteLine("  ✓ Login successful");

        // 4️⃣ Sanctum CSRF cookie
        Console.WriteLine("[4/6] Refreshing Sanctum CSRF...");
        var sanctum = await client.GetAsync("/sanctum/csrf-cookie");
        sanctum.EnsureSuccessStatusCode();
        Console.WriteLine("  ✓ Sanctum CSRF refreshed");

        // 5️⃣ Extract XSRF token
        Console.WriteLine("[5/6] Extracting cookies...");
        var jar = cookies.GetCookies(new Uri(baseUrl));

        string xsrf = null!;
        foreach (Cookie c in jar)
            if (c.Name == "XSRF-TOKEN")
                xsrf = Uri.UnescapeDataString(c.Value);

        if (xsrf == null)
            throw new Exception("XSRF token missing");

        // 6️⃣ Create client (🚨 browser-like headers)
        Console.WriteLine("[6/6] Creating client...");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrf);
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Origin", baseUrl);
        client.DefaultRequestHeaders.Add("Referer", $"{baseUrl}/clients");

        var create = await client.PostAsync(
            "/api/clients",
            new StringContent(clientJson, Encoding.UTF8, "application/json")
        );

        var body = await create.Content.ReadAsStringAsync();
        Console.WriteLine($"== Response Status: {(int)create.StatusCode} ==");
        Console.WriteLine(body);

        if (!create.IsSuccessStatusCode)
            throw new Exception("Client creation failed");

        Console.WriteLine("✅ SUCCESS: Client created in MijnDiAd");
    }

    static string GenerateTotp(string secret)
    {
        var key = Base32Decode(secret);
        var counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var data = BitConverter.GetBytes(counter);
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
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var buffer = 0;
        var bits = 0;
        var output = new byte[input.Length * 5 / 8];
        int index = 0;

        foreach (char c in input.TrimEnd('='))
        {
            int val = chars.IndexOf(c);
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
