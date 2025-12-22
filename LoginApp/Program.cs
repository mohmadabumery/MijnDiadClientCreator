using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.IO;

class LoginProgram
{
    static async Task Main(string[] args)
    {
        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        var totp = GenerateTotp(Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET"));

        Console.WriteLine("== MijnDiAd Auto-Login ==");

        var cookieContainer = new CookieContainer();

        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        // 1️⃣ FETCH LOGIN PAGE
        Console.WriteLine("[1/4] Fetching initial session cookies...");
        var loginPageResponse = await client.GetAsync(
            $"https://{tenant}.mijndiad.nl/login"
        );
        loginPageResponse.EnsureSuccessStatusCode();
        var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // 2️⃣ EXTRACT CSRF TOKEN
        Console.WriteLine("[2/4] Extracting CSRF token...");
        var csrfMatch = Regex.Match(
            loginPageHtml,
            "<meta name=\"csrf-token\" content=\"([^\"]+)\""
        );

        if (!csrfMatch.Success)
        {
            Console.WriteLine("❌ CSRF token not found in login page");
            Environment.Exit(1);
        }

        var csrfToken = csrfMatch.Groups[1].Value;
        Console.WriteLine($"✓ CSRF Token extracted");

        // 3️⃣ LOGIN
        Console.WriteLine("[3/4] Logging in to MijnDiAd...");
        Console.WriteLine($"✓ Generated TOTP: {totp}");

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
            Environment.Exit(1);
        }

        // 4️⃣ EXTRACT AND SAVE COOKIES
        Console.WriteLine("[4/4] Extracting authenticated session cookies...");

        var cookies = cookieContainer.GetCookies(
            new Uri($"https://{tenant}.mijndiad.nl")
        );

        string sessionCookie = null;
        string xsrfToken = null;

        foreach (Cookie cookie in cookies)
        {
            if (cookie.Name == $"{tenant}_session")
            {
                sessionCookie = cookie.Value;
                Console.WriteLine($"✓ Got session cookie: {sessionCookie.Substring(0, 20)}...");
            }
            if (cookie.Name == "XSRF-TOKEN")
            {
                xsrfToken = cookie.Value;
                Console.WriteLine($"✓ Got XSRF token: {xsrfToken.Substring(0, 20)}...");
            }
        }

        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
        {
            Console.WriteLine("❌ Auth session cookies not found");
            Environment.Exit(1);
        }

        // Save cookies to GitHub environment for next workflow
        var githubOutput = Environment.GetEnvironmentVariable("GITHUB_OUTPUT");
        if (!string.IsNullOrEmpty(githubOutput))
        {
            File.AppendAllText(githubOutput, $"SESSION_COOKIE={sessionCookie}\n");
            File.AppendAllText(githubOutput, $"XSRF_TOKEN={xsrfToken}\n");
            Console.WriteLine("✓ Cookies saved to GitHub output");
        }

        Console.WriteLine("\n✅ Login successful!");
        Console.WriteLine("✅ Session cookies are ready for client creation");
    }

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
