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
        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        var totp = GenerateTotp(Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET"));

        Console.WriteLine("== Dynamics → MijnDiAd Automation with Auto-Login ==");

        var cookieContainer = new CookieContainer();

        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        // ----------------------------------------------------
        // 1️⃣ FETCH LOGIN PAGE (SETS SESSION + XSRF COOKIE)
        // ----------------------------------------------------
        Console.WriteLine("[1/4] Fetching initial session cookies...");

        var loginPageResponse = await client.GetAsync(
            $"https://{tenant}.mijndiad.nl/login"
        );

        loginPageResponse.EnsureSuccessStatusCode();

        var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // ----------------------------------------------------
        // 2️⃣ EXTRACT CSRF TOKEN FROM META TAG
        // ----------------------------------------------------
        Console.WriteLine("[2/4] Extracting CSRF token...");

        var csrfMatch = Regex.Match(
            loginPageHtml,
            "<meta name=\"csrf-token\" content=\"([^\"]+)\""
        );

        if (!csrfMatch.Success)
        {
            Console.WriteLine("❌ CSRF token not found in login page");
            return;
        }

        var csrfToken = csrfMatch.Groups[1].Value;
        Console.WriteLine($"CSRF Token: {csrfToken}");

        // ----------------------------------------------------
        // 3️⃣ PREPARE LOGIN REQUEST
        // ----------------------------------------------------
        Console.WriteLine("[3/4] Logging in to MijnDiAd...");
        Console.WriteLine($"Generated TOTP: {totp}");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/login");

        var payload = new
        {
            email = username,
            password = password,
            totp_code = totp
        };

        var json = JsonSerializer.Serialize(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/login",
            content
        );

        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed: {(int)response.StatusCode}");
            Console.WriteLine(responseBody);
            return;
        }

        // ----------------------------------------------------
        // 4️⃣ CONFIRM AUTH SESSION
        // ----------------------------------------------------
        Console.WriteLine("[4/4] Verifying authenticated session...");

        var cookies = cookieContainer.GetCookies(
            new Uri($"https://{tenant}.mijndiad.nl")
        );

        if (cookies["lngvty_session"] == null)
        {
            Console.WriteLine("❌ Auth session cookie not found");
            return;
        }

        Console.WriteLine("✅ Login successful");
        Console.WriteLine("✅ Authenticated session cookie confirmed");
    }

    // ----------------------------------------------------
    // 🔐 SIMPLE TOTP GENERATOR (RFC 6238)
    // ----------------------------------------------------
    static string GenerateTotp(string base32Secret)
    {
        var key = Base32Decode(base32Secret);
        var timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;

        var data = BitConverter.GetBytes(timestep);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(data);

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
