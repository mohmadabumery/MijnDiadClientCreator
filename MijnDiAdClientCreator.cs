using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

class MijnDiAdClientCreator
{
    static async Task Main(string[] args)
    {
        if (args.Length < 2 || args[0] != "--json")
        {
            Console.WriteLine("Usage: dotnet run -- --json '{\"firstname\":\"John\", ...}'");
            return;
        }

        string clientJson = args[1];

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        // 1️⃣ Fetch login page
        Console.WriteLine("[1/3] Fetching login page...");
        var loginPage = await client.GetAsync($"https://{tenant}.mijndiad.nl/login");
        loginPage.EnsureSuccessStatusCode();
        var html = await loginPage.Content.ReadAsStringAsync();

        // 2️⃣ Extract CSRF token
        Console.WriteLine("[2/3] Extracting CSRF token...");
        var csrfMatch = Regex.Match(html, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!csrfMatch.Success)
        {
            Console.WriteLine("❌ CSRF token not found");
            Environment.Exit(1);
        }
        var csrfToken = csrfMatch.Groups[1].Value;

        // 3️⃣ Login
        Console.WriteLine("[3/3] Logging in...");
        var totp = GenerateTotp(totpSecret);

        var loginPayload = new
        {
            email = username,
            password = password,
            totp_code = totp
        };

        var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/login");

        var loginResponse = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/login", loginContent);
        var loginResponseBody = await loginResponse.Content.ReadAsStringAsync();

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed: {loginResponse.StatusCode}");
            Console.WriteLine(loginResponseBody);
            Environment.Exit(1);
        }

        // Extract session cookie & XSRF token
        var cookies = cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl"));
        string sessionCookie = null, xsrfToken = null;
        foreach (Cookie cookie in cookies)
        {
            if (cookie.Name == $"{tenant}_session") sessionCookie = cookie.Value;
            if (cookie.Name == "XSRF-TOKEN") xsrfToken = cookie.Value;
        }

        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
        {
            Console.WriteLine("❌ Session cookies missing after login");
            Environment.Exit(1);
        }

        Console.WriteLine("✓ Login successful, session ready!");

        // 4️⃣ Create client
        Console.WriteLine("Creating client...");
        var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");

        // Attach XSRF token for the POST request
        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrfToken);
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/");

        var createResponse = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/clients", clientContent);
        var createBody = await createResponse.Content.ReadAsStringAsync();

        if (!createResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("❌ Client creation failed");
            Console.WriteLine(createBody);
            Environment.Exit(1);
        }

        Console.WriteLine("✅ Client successfully created!");
        Console.WriteLine(createBody);
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
