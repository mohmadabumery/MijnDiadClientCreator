using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length < 2 || args[0] != "--json")
            throw new Exception("Usage: dotnet run -- --json '{...}'");

        string clientJson = args[1];

        string tenant = Env("MIJNDIAD_TENANT");
        string email = Env("MIJNDIAD_USERNAME");
        string password = Env("MIJNDIAD_PASSWORD");
        string totpSecret = Env("MIJNDIAD_TOTP_SECRET");

        Console.WriteLine("== MijnDiAd Laravel Automation ==");

        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookies,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        for (int attempt = 1; attempt <= 2; attempt++)
        {
            Console.WriteLine($"\n--- Attempt {attempt} ---");

            await BootstrapSanctum(client, tenant);
            await Login(client, tenant, email, password, totpSecret);

            if (await CreateClient(client, tenant, cookies, clientJson))
            {
                Console.WriteLine("\n✅ CLIENT CREATED SUCCESSFULLY");
                return;
            }

            Console.WriteLine("⚠ Session expired, retrying...");
        }

        throw new Exception("❌ Client creation failed after retry");
    }

    /* ---------------- SANCTUM ---------------- */

    static async Task BootstrapSanctum(HttpClient client, string tenant)
    {
        Console.WriteLine("[1/4] Bootstrapping Sanctum...");
        await client.GetAsync($"https://{tenant}.mijndiad.nl/sanctum/csrf-cookie");
    }

    /* ---------------- LOGIN ---------------- */

    static async Task Login(HttpClient client, string tenant, string email, string password, string totpSecret)
{
    Console.WriteLine("[2/4] Logging in (browser-style)...");

    var form = new Dictionary<string, string>
    {
        ["email"] = email,
        ["password"] = password,
        ["totp_code"] = GenerateTotp(totpSecret)
    };

    var content = new FormUrlEncodedContent(form);

    client.DefaultRequestHeaders.Clear();
    client.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml");
    client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/login");

    var response = await client.PostAsync(
        $"https://{tenant}.mijndiad.nl/login",
        content
    );

    if (!response.IsSuccessStatusCode)
    {
        var body = await response.Content.ReadAsStringAsync();
        Console.WriteLine(body);
        throw new Exception("Login failed");
    }

    Console.WriteLine("✓ Login successful");
}


    /* ---------------- CREATE CLIENT ---------------- */

    static async Task<bool> CreateClient(
        HttpClient client,
        string tenant,
        CookieContainer cookies,
        string json)
    {
        Console.WriteLine("[3/4] Preparing client request...");

        var uri = new Uri($"https://{tenant}.mijndiad.nl");

        var xsrfCookie = cookies.GetCookies(uri)["XSRF-TOKEN"]?.Value;
        if (xsrfCookie == null)
            throw new Exception("XSRF-TOKEN cookie missing");

        string xsrfHeader = Uri.UnescapeDataString(xsrfCookie);

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrfHeader);
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        Console.WriteLine("[4/4] Creating client...");

        var resp = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/clients",
            new StringContent(json, Encoding.UTF8, "application/json")
        );

        string body = await resp.Content.ReadAsStringAsync();

        Console.WriteLine($"== STATUS {(int)resp.StatusCode} ==");
        Console.WriteLine(body);

        return resp.IsSuccessStatusCode;
    }

    /* ---------------- HELPERS ---------------- */

    static string Env(string k)
        => Environment.GetEnvironmentVariable(k)
           ?? throw new Exception($"{k} not set");

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
