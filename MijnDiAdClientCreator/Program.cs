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
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);

        /* -------------------- 1. GET LOGIN PAGE -------------------- */
        Console.WriteLine("[1/4] Fetching login page...");
        var loginPage = await client.GetStringAsync($"https://{tenant}.mijndiad.nl/login");

        var csrf = Regex.Match(loginPage, "csrf-token\" content=\"([^\"]+)\"").Groups[1].Value;
        if (string.IsNullOrEmpty(csrf)) throw new Exception("CSRF not found");

        Console.WriteLine("✓ CSRF token extracted");

        /* -------------------- 2. LOGIN -------------------- */
        Console.WriteLine("[2/4] Logging in...");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrf);
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        var loginPayload = JsonSerializer.Serialize(new
        {
            email = username,
            password = password,
            totp_code = GenerateTotp(totpSecret)
        });

        var loginResp = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/login",
            new StringContent(loginPayload, Encoding.UTF8, "application/json")
        );

        if (!loginResp.IsSuccessStatusCode)
            throw new Exception("Login failed");

        Console.WriteLine("✓ Login successful");

        /* -------------------- 3. VISIT DASHBOARD -------------------- */
        Console.WriteLine("[3/4] Visiting dashboard...");

        var dashHtml = await client.GetStringAsync($"https://{tenant}.mijndiad.nl/dashboard");

        var xsrf = Regex.Match(dashHtml, "csrf-token\" content=\"([^\"]+)\"").Groups[1].Value;
        if (string.IsNullOrEmpty(xsrf)) throw new Exception("XSRF not found");

        Console.WriteLine("✓ CSRF refreshed from dashboard");

        /* -------------------- 4. CREATE CLIENT -------------------- */
        Console.WriteLine("[4/4] Creating client...");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrf); // 🔥 THIS IS THE KEY
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Referrer =
            new Uri($"https://{tenant}.mijndiad.nl/clients/create");

        var resp = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/clients",
            new StringContent(clientJson, Encoding.UTF8, "application/json")
        );

        var body = await resp.Content.ReadAsStringAsync();

        Console.WriteLine($"== STATUS {(int)resp.StatusCode} ==");
        Console.WriteLine(body);

        if (!resp.IsSuccessStatusCode)
            throw new Exception("❌ Client creation failed");

        Console.WriteLine("✅ Client created successfully");
    }

    static string GetEnv(string key) =>
        Environment.GetEnvironmentVariable(key)
        ?? throw new Exception($"{key} not set");

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
        int buffer = 0, bits = 0, index = 0;
        var output = new byte[input.Length * 5 / 8];

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
