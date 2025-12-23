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
            Console.WriteLine("Usage: dotnet run -- --json '{\"firstname\":\"John\", ...}'");
            return;
        }

        string clientJson = args[1];

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? throw new Exception("MIJNDIAD_TENANT not set");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") ?? throw new Exception("MIJNDIAD_USERNAME not set");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") ?? throw new Exception("MIJNDIAD_PASSWORD not set");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") ?? throw new Exception("MIJNDIAD_TOTP_SECRET not set");

        const int maxRetries = 3;

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            Console.WriteLine($"--- Attempt {attempt} ---");
            try
            {
                // Perform login and get dynamic session + XSRF
                var (sessionCookie, xsrfToken) = await LoginAndGetCookies(tenant, username, password, totpSecret);

                // Try creating client
                bool success = await CreateClient(tenant, sessionCookie, xsrfToken, clientJson);
                if (success) return;

                Console.WriteLine("⚠ CSRF/session expired — retrying login...");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Login or client creation failed: {ex.Message}");
                if (attempt == maxRetries)
                    Environment.Exit(1);
            }
        }
    }

    static async Task<(string sessionCookie, string xsrfToken)> LoginAndGetCookies(string tenant, string username, string password, string totpSecret)
    {
        var totp = GenerateTotp(totpSecret);
        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler { CookieContainer = cookieContainer, UseCookies = true, AutomaticDecompression = DecompressionMethods.All };
        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);

        // Fetch login page
        var loginPageHtml = await (await client.GetAsync($"https://{tenant}.mijndiad.nl/login")).Content.ReadAsStringAsync();
        var csrfMatch = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!csrfMatch.Success) throw new Exception("CSRF token not found on login page");
        var csrfToken = csrfMatch.Groups[1].Value;

        // Login
        var loginPayload = new { email = username, password = password, totp_code = totp };
        var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/login");

        var loginResponse = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/login", loginContent);
        var loginBody = await loginResponse.Content.ReadAsStringAsync();
        if (!loginResponse.IsSuccessStatusCode) throw new Exception($"Login failed: {loginBody}");

        // Extract session cookie + XSRF token
        string sessionCookie = null, xsrfToken = null;
        var cookies = cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl"));
        foreach (Cookie c in cookies)
        {
            if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
            if (c.Name == "XSRF-TOKEN") xsrfToken = Uri.UnescapeDataString(c.Value);
        }
        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            throw new Exception("Session cookies not found after login");

        // Optional: visit dashboard to refresh session
        var dashboardHtml = await (await client.GetAsync($"https://{tenant}.mijndiad.nl/dashboard")).Content.ReadAsStringAsync();
        var dashCsrfMatch = Regex.Match(dashboardHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (dashCsrfMatch.Success) xsrfToken = dashCsrfMatch.Groups[1].Value;

        return (sessionCookie, xsrfToken);
    }

    static async Task<bool> CreateClient(string tenant, string sessionCookie, string xsrfToken, string clientJson)
    {
        using var apiClient = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Post, $"https://{tenant}.mijndiad.nl/api/clients");
        request.Content = new StringContent(clientJson, Encoding.UTF8, "application/json");

        request.Headers.Add("Accept", "application/json, text/plain, */*");
        request.Headers.Add("X-Requested-With", "XMLHttpRequest");
        request.Headers.Add("x-csrf-token", xsrfToken);
        request.Headers.Add("Origin", $"https://{tenant}.mijndiad.nl");
        request.Headers.Add("Referer", $"https://{tenant}.mijndiad.nl/clients/create");
        request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        request.Headers.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

        var response = await apiClient.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"\n== Response Status: {(int)response.StatusCode} ==");
        Console.WriteLine(body);

        return response.IsSuccessStatusCode;
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
            int charIndex = alphabet.IndexOf(c);
            if (charIndex < 0) continue;
            bitBuffer = (bitBuffer << 5) | charIndex;
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
