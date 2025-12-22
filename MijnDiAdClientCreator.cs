using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;

class MijnDiAdClientCreator
{
    static async Task Main(string[] args)
    {
        // === Environment Variables ===
        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        if (string.IsNullOrEmpty(tenant) || string.IsNullOrEmpty(username) ||
            string.IsNullOrEmpty(password) || string.IsNullOrEmpty(totpSecret))
        {
            Console.WriteLine("❌ Missing environment variables");
            Environment.Exit(1);
        }

        // === Get client JSON from args ===
        string clientJson = null;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--json")
            {
                clientJson = args[i + 1];
                break;
            }
        }

        if (string.IsNullOrEmpty(clientJson))
        {
            Console.WriteLine("❌ Missing --json input");
            Environment.Exit(1);
        }

        // === Setup HTTP client with cookie container ===
        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };
        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        // === 1️⃣ Fetch login page ===
        Console.WriteLine("[1/3] Fetching login page...");
        var loginPage = await client.GetAsync($"https://{tenant}.mijndiad.nl/login");
        loginPage.EnsureSuccessStatusCode();
        var html = await loginPage.Content.ReadAsStringAsync();

        // === 2️⃣ Extract CSRF token ===
        var csrfMatch = Regex.Match(html, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!csrfMatch.Success)
        {
            Console.WriteLine("❌ CSRF token not found");
            Environment.Exit(1);
        }
        var csrfToken = csrfMatch.Groups[1].Value;

        // === 3️⃣ Login ===
        Console.WriteLine("[2/3] Logging in...");
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/login");

        var loginPayload = new Dictionary<string, object>
        {
            ["email"] = username,
            ["password"] = password,
            ["totp_code"] = GenerateTotp(totpSecret)
        };

        var loginJson = JsonSerializer.Serialize(loginPayload);
        var loginContent = new StringContent(loginJson, Encoding.UTF8, "application/json");

        var loginResponse = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/login", loginContent);
        var loginBody = await loginResponse.Content.ReadAsStringAsync();

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed ({(int)loginResponse.StatusCode})");
            Console.WriteLine(loginBody);
            Environment.Exit(1);
        }

        Console.WriteLine("✓ Logged in successfully");

        // === 4️⃣ Create client ===
        Console.WriteLine("[3/3] Creating client...");
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/");

        var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
        var createResponse = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/clients", clientContent);
        var createBody = await createResponse.Content.ReadAsStringAsync();

        if (!createResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Client creation failed ({(int)createResponse.StatusCode})");
            Console.WriteLine(createBody);
            Environment.Exit(1);
        }

        Console.WriteLine("✅ Client successfully created!");
        Console.WriteLine(createBody);
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
            bitBuffer = (bitBuffer << 5) | alphabet.IndexOf(c);
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
