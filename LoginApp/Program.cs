using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

class LoginProgram
{
    static async Task Main(string[] args)
    {
        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        var totp = GenerateTotp(Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET"));

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
        var loginPageResponse = await client.GetAsync(
            $"https://{tenant}.mijndiad.nl/login"
        );
        loginPageResponse.EnsureSuccessStatusCode();
        var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // 2️⃣ Extract CSRF token
        var csrfMatch = Regex.Match(
            loginPageHtml,
            "<meta name=\"csrf-token\" content=\"([^\"]+)\""
        );

        if (!csrfMatch.Success)
            Environment.Exit(1);

        var csrfToken = csrfMatch.Groups[1].Value;

        // 3️⃣ Login
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

        if (!response.IsSuccessStatusCode)
            Environment.Exit(1);

        // 4️⃣ Extract cookies
        var cookies = cookieContainer.GetCookies(
            new Uri($"https://{tenant}.mijndiad.nl")
        );

        string sessionCookie = null;
        string xsrfToken = null;

        foreach (Cookie cookie in cookies)
        {
            if (cookie.Name == $"{tenant}_session")
                sessionCookie = cookie.Value;

            if (cookie.Name == "XSRF-TOKEN")
                xsrfToken = cookie.Value;
        }

        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            Environment.Exit(1);

        // ✅ FINAL & ONLY OUTPUT (GitHub Actions reads this)
        var output = new
        {
            session_cookie = sessionCookie,
            xsrf_token = xsrfToken
        };

        Console.WriteLine(JsonSerializer.Serialize(output));
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
