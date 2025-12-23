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
            Console.WriteLine("Usage: dotnet run -- --json '{...}'");
            return;
        }

        string clientJson = args[1];

        string tenant = GetEnv("MIJNDIAD_TENANT");
        string username = GetEnv("MIJNDIAD_USERNAME");
        string password = GetEnv("MIJNDIAD_PASSWORD");
        string totpSecret = GetEnv("MIJNDIAD_TOTP_SECRET");

        Console.WriteLine("== MijnDiAd Auto Login + Client Creation ==");

        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookies,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        // 🔁 One retry allowed if CSRF expires
        for (int attempt = 1; attempt <= 2; attempt++)
        {
            Console.WriteLine($"\n--- Attempt {attempt} ---");

            string csrf = await LoginAndGetCsrf(client, tenant, username, password, totpSecret);

            bool success = await CreateClient(client, tenant, csrf, clientJson);

            if (success)
            {
                Console.WriteLine("\n✅ Client created successfully");
                return;
            }

            Console.WriteLine("⚠ CSRF/session expired — retrying login...");
        }

        throw new Exception("❌ Client creation failed after retry");
    }

    /* ---------------- LOGIN + CSRF ---------------- */

    static async Task<string> LoginAndGetCsrf(
        HttpClient client,
        string tenant,
        string username,
        string password,
        string totpSecret)
    {
        // 1️⃣ Fetch login page
        Console.WriteLine("[1/4] Fetching login page...");
        string loginHtml = await client.GetStringAsync($"https://{tenant}.mijndiad.nl/login");

        string csrf = ExtractCsrf(loginHtml);

        // 2️⃣ Login
        Console.WriteLine("[2/4] Logging in...");
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("x-csrf-token", csrf);
        client.DefaultRequestHeaders.Referrer =
            new Uri($"https://{tenant}.mijndiad.nl/login");

        var loginPayload = new
        {
            email = username,
            password = password,
            totp_code = GenerateTotp(totpSecret)
        };

        var loginResp = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/login",
            new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json")
        );

        if (!loginResp.IsSuccessStatusCode)
            throw new Exception("Login failed");

        Console.WriteLine("✓ Login successful");

        // 3️⃣ Visit dashboard → refresh CSRF
        Console.WriteLine("[3/4] Visiting dashboard...");
        string dashboardHtml = await client.GetStringAsync(
            $"https://{tenant}.mijndiad.nl/dashboard");

        csrf = ExtractCsrf(dashboardHtml);
        Console.WriteLine("✓ CSRF refreshed from dashboard");

        return csrf;
    }

    /* ---------------- CREATE CLIENT ---------------- */

    static async Task<bool> CreateClient(
        HttpClient client,
        string tenant,
        string csrf,
        string clientJson)
    {
        Console.WriteLine("[4/4] Creating client...");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("x-csrf-token", csrf); // 🔑 CORRECT HEADER
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Referrer =
            new Uri($"https://{tenant}.mijndiad.nl/clients/create");

        var resp = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/clients",
            new StringContent(clientJson, Encoding.UTF8, "application/json")
        );

        string body = await resp.Content.ReadAsStringAsync();

        Console.WriteLine($"== STATUS {(int)resp.StatusCode} ==");
        Console.WriteLine(body);

        if (resp.IsSuccessStatusCode)
            return true;

        // Laravel CSRF/session expiry responses
        if ((int)resp.StatusCode == 401 || (int)resp.StatusCode == 419 || (int)resp.StatusCode == 422)
            return false;

        throw new Exception("Unexpected API error");
    }

    /* ---------------- HELPERS ---------------- */

    static string ExtractCsrf(string html)
    {
        var match = Regex.Match(html,
            "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!match.Success)
            throw new Exception("CSRF token not found");
        return match.Groups[1].Value;
    }

    static string GetEnv(string name)
        => Environment.GetEnvironmentVariable(name)
           ?? throw new Exception($"{name} not set");

    /* ---------------- TOTP ---------------- */

    static string GenerateTotp(string secret)
    {
        var key = Base32Decode(secret);
        long timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
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
        int bits = 0, value = 0, index = 0;
        var output = new byte[input.Length * 5 / 8];

        foreach (char c in input.TrimEnd('='))
        {
            int idx = alphabet.IndexOf(c);
            if (idx < 0) continue;

            value = (value << 5) | idx;
            bits += 5;

            if (bits >= 8)
            {
                output[index++] = (byte)(value >> (bits - 8));
                bits -= 8;
            }
        }

        Array.Resize(ref output, index);
        return output;
    }
}
