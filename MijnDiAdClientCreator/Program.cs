
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.IO;

class Program
{
    static async Task<int> Main(string[] args)
    {
        if (args.Length < 2 || args[0] != "--json")
        {
            Console.WriteLine("Usage: dotnet run -- --json '{\"firstname\":\"John\",...}'");
            return 1;
        }

        string clientJson = args[1];

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT")!;
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME")!;
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD")!;
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET")!;

        string sessionCookie = Environment.GetEnvironmentVariable("SESSION_COOKIE")!;
        string xsrfToken = Environment.GetEnvironmentVariable("XSRF_TOKEN")!;

        // If SESSION_COOKIE/XSRF_TOKEN not provided, do login
        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
        {
            (sessionCookie, xsrfToken) = await LoginAsync(tenant, username, password, totpSecret);
        }

        bool result = await CreateClientAsync(tenant, sessionCookie, xsrfToken, clientJson);
        return result ? 0 : 1;
    }

    static async Task<(string sessionCookie, string xsrfToken)> LoginAsync(string tenant, string username, string password, string totpSecret)
    {
        Console.WriteLine("== MijnDiAd Login ==");

        string totp = GenerateTotp(totpSecret);

        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler { CookieContainer = cookieContainer };
        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        // 1️⃣ Get login page
        var loginPageResponse = await client.GetAsync($"https://{tenant}.mijndiad.nl/login");
        loginPageResponse.EnsureSuccessStatusCode();
        string loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // 2️⃣ Extract CSRF token
        var csrfMatch = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!csrfMatch.Success)
        {
            Console.WriteLine("❌ CSRF token not found");
            Environment.Exit(1);
        }
        string csrfToken = csrfMatch.Groups[1].Value;

        // 3️⃣ Login
        var payload = new { email = username, password = password, totp_code = totp };
        var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");

        var response = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/login", content);
        string responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine("❌ Login failed");
            Console.WriteLine(responseBody);
            Environment.Exit(1);
        }

        // 4️⃣ Extract cookies
        string sessionCookie = null!;
        string xsrfToken = null!;
        foreach (Cookie c in cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl")))
        {
            if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
            if (c.Name == "XSRF-TOKEN") xsrfToken = c.Value;
        }

        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
        {
            Console.WriteLine("❌ Session cookies missing after login");
            Environment.Exit(1);
        }

        Console.WriteLine("✅ Login successful");
        return (sessionCookie, xsrfToken);
    }

    static async Task<bool> CreateClientAsync(string tenant, string sessionCookie, string xsrfToken, string clientJson)
    {
        Console.WriteLine("== Creating client ==");

        var handler = new HttpClientHandler { CookieContainer = new CookieContainer() };
        handler.CookieContainer.Add(new Uri($"https://{tenant}.mijndiad.nl"), new Cookie($"{tenant}_session", sessionCookie));
        handler.CookieContainer.Add(new Uri($"https://{tenant}.mijndiad.nl"), new Cookie("XSRF-TOKEN", xsrfToken));

        using var client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrfToken);

        var content = new StringContent(clientJson, Encoding.UTF8, "application/json");
        var response = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/clients", content);

        string body = await response.Content.ReadAsStringAsync();

        if (response.IsSuccessStatusCode)
        {
            Console.WriteLine("✅ Client created successfully!");
            return true;
        }
        else
        {
            Console.WriteLine("❌ Client creation failed");
            Console.WriteLine(body);
            return false;
        }
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

        int otp = binary % 1_000_000;
        return otp.ToString("D6");
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
