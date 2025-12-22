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
        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "";
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") ?? "";
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") ?? "";
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") ?? "";

        if (string.IsNullOrEmpty(tenant) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            Console.WriteLine("❌ Missing required environment variables");
            return 1;
        }

        // Parse JSON input
        string jsonInput = "{}";
        if (args.Length >= 2 && args[0] == "--json")
        {
            jsonInput = args[1];
        }

        try
        {
            var cookieContainer = new CookieContainer();
            using var handler = new HttpClientHandler { CookieContainer = cookieContainer };
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(30);

            // 1️⃣ Fetch login page
            Console.WriteLine("[1/3] Fetching login page...");
            var loginPage = await client.GetStringAsync($"https://{tenant}.mijndiad.nl/login");

            // 2️⃣ Extract CSRF token
            var csrfMatch = Regex.Match(loginPage, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!csrfMatch.Success)
            {
                Console.WriteLine("❌ CSRF token not found");
                return 1;
            }
            var csrfToken = csrfMatch.Groups[1].Value;
            Console.WriteLine("✓ CSRF token extracted");

            // 3️⃣ Login
            var totp = GenerateTotp(totpSecret);
            var payload = new { email = username, password = password, totp_code = totp };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
            client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
            client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
            client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
            client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/login");

            var response = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/login", content);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Login failed: {(int)response.StatusCode}");
                Console.WriteLine(responseBody);
                return 1;
            }
            Console.WriteLine("✓ Logged in successfully");

            // 4️⃣ Extract cookies
            string sessionCookie = null;
            string xsrfToken = null;
            foreach (Cookie cookie in cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl")))
            {
                if (cookie.Name.EndsWith("_session")) sessionCookie = cookie.Value;
                if (cookie.Name == "XSRF-TOKEN") xsrfToken = cookie.Value;
            }

            if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            {
                Console.WriteLine("❌ Session cookies not found");
                return 1;
            }
            Console.WriteLine("✓ Session cookies extracted");

            // 5️⃣ Create client
            Console.WriteLine("[5/5] Creating client...");
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
            client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrfToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

            var clientContent = new StringContent(jsonInput, Encoding.UTF8, "application/json");
            var clientResponse = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/clients", clientContent);
            var clientResponseBody = await clientResponse.Content.ReadAsStringAsync();

            if (!clientResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("❌ Client creation failed");
                Console.WriteLine(clientResponseBody);
                return 1;
            }

            Console.WriteLine("✅ Client created successfully");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Exception: {ex.Message}");
            return 1;
        }
    }

    static string GenerateTotp(string base32Secret)
    {
        if (string.IsNullOrEmpty(base32Secret)) return "000000";

        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var key = new byte[base32Secret.Length * 5 / 8];
        int bitBuffer = 0, bitCount = 0, index = 0;

        foreach (char c in base32Secret.TrimEnd('='))
        {
            bitBuffer = (bitBuffer << 5) | alphabet.IndexOf(c);
            bitCount += 5;
            if (bitCount >= 8)
            {
                key[index++] = (byte)(bitBuffer >> (bitCount - 8));
                bitCount -= 8;
            }
        }
        Array.Resize(ref key, index);

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

        int otp = binary % 1_000_000;
        return otp.ToString("D6");
    }
}
