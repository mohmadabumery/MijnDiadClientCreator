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
            Environment.Exit(1);
        }

        string clientJson = args[1];

        string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT")
            ?? throw new Exception("MIJNDIAD_TENANT not set");
        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME")
            ?? throw new Exception("MIJNDIAD_USERNAME not set");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD")
            ?? throw new Exception("MIJNDIAD_PASSWORD not set");
        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET")
            ?? throw new Exception("MIJNDIAD_TOTP_SECRET not set");

        string totp = GenerateTotp(totpSecret);

        Console.WriteLine("== MijnDiAd Auto Login + Client Creation ==");

        // ✅ ONE cookie jar for everything
        var cookies = new CookieContainer();

        var handler = new HttpClientHandler
        {
            CookieContainer = cookies,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        // ----------------------------------------------------
        // 1️⃣ GET LOGIN PAGE (establish session + CSRF cookie)
        // ----------------------------------------------------
        Console.WriteLine("[1/4] Fetching login page...");

        var loginPage = await client.GetAsync($"https://{tenant}.mijndiad.nl/login");
        loginPage.EnsureSuccessStatusCode();

        string loginHtml = await loginPage.Content.ReadAsStringAsync();

        var csrfMatch = Regex.Match(
            loginHtml,
            "<meta name=\"csrf-token\" content=\"([^\"]+)\""
        );

        if (!csrfMatch.Success)
            throw new Exception("CSRF token not found");

        string csrfToken = csrfMatch.Groups[1].Value;
        Console.WriteLine("✓ CSRF token extracted");

        // ----------------------------------------------------
        // 2️⃣ LOGIN
        // ----------------------------------------------------
        Console.WriteLine("[2/4] Logging in...");

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

        var loginResponse = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/login",
            new StringContent(
                JsonSerializer.Serialize(loginPayload),
                Encoding.UTF8,
                "application/json"
            )
        );

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("❌ Login failed");
            Console.WriteLine(await loginResponse.Content.ReadAsStringAsync());
            Environment.Exit(1);
        }

        Console.WriteLine("✓ Login successful");

        // ----------------------------------------------------
        // 3️⃣ VISIT DASHBOARD (CRITICAL – refreshes session)
        // ----------------------------------------------------
        Console.WriteLine("[3/4] Visiting dashboard...");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "text/html");

        var dashboard = await client.GetAsync($"https://{tenant}.mijndiad.nl/dashboard");
        dashboard.EnsureSuccessStatusCode();

        string dashboardHtml = await dashboard.Content.ReadAsStringAsync();

        var dashCsrf = Regex.Match(
            dashboardHtml,
            "<meta name=\"csrf-token\" content=\"([^\"]+)\""
        );

        if (dashCsrf.Success)
        {
            csrfToken = dashCsrf.Groups[1].Value;
            Console.WriteLine("✓ CSRF refreshed from dashboard");
        }

        // ----------------------------------------------------
        // 4️⃣ CREATE CLIENT (SAME CLIENT, SAME SESSION)
        // ----------------------------------------------------
        Console.WriteLine("[4/4] Creating client...");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/clients/create");

        var createResponse = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/clients",
            new StringContent(clientJson, Encoding.UTF8, "application/json")
        );

        string createBody = await createResponse.Content.ReadAsStringAsync();

        Console.WriteLine($"== STATUS {(int)createResponse.StatusCode} ==");
        Console.WriteLine(createBody);

        if (!createResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("❌ Client creation failed");
            Environment.Exit(1);
        }

        Console.WriteLine("✅ CLIENT CREATED SUCCESSFULLY");
    }

    // ----------------------------------------------------
    // 🔐 TOTP
    // ----------------------------------------------------
    static string GenerateTotp(string base32)
    {
        var key = Base32Decode(base32);
        long timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;

        byte[] data = BitConverter.GetBytes(timestep);
        if (BitConverter.IsLittleEndian) Array.Reverse(data);

        using var hmac = new System.Security.Cryptography.HMACSHA1(key);
        byte[] hash = hmac.ComputeHash(data);

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
