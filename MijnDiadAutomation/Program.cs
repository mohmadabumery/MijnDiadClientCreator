using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Missing JSON file argument");
            return;
        }

        string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";
        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookies,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.BaseAddress = new Uri($"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        Console.WriteLine("[1/4] Fetching session...");
        await client.GetAsync("/login");

        string xsrf = cookies
            .GetCookies(new Uri(client.BaseAddress.ToString()))["XSRF-TOKEN"]?.Value;

        if (xsrf == null)
        {
            Console.WriteLine("❌ No XSRF token received");
            return;
        }

        Console.WriteLine("[2/4] Logging in...");

        var loginPayload = new
        {
            email = username,
            password = password,
            totp_code = GenerateTOTP(totpSecret),
            tenant = tenant
        };

        var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/api/login");
        loginRequest.Content = new StringContent(
            JsonSerializer.Serialize(loginPayload),
            Encoding.UTF8,
            "application/json"
        );
        loginRequest.Headers.Add("X-CSRF-TOKEN", xsrf); // ✅ Send raw token
        loginRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");

        var loginResponse = await client.SendAsync(loginRequest);
        string loginBody = await loginResponse.Content.ReadAsStringAsync();

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine($"❌ Login failed: {loginResponse.StatusCode}");
            Console.WriteLine(loginBody);
            return;
        }

        Console.WriteLine("✓ Logged in");

        Console.WriteLine("[3/4] Creating client...");
        string jsonBody = await File.ReadAllTextAsync(args[0]);

        var createRequest = new HttpRequestMessage(HttpMethod.Post, "/api/clients");
        createRequest.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        createRequest.Headers.Add("X-CSRF-TOKEN", xsrf); // ✅ raw token again
        createRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");

        var createResponse = await client.SendAsync(createRequest);
        string responseBody = await createResponse.Content.ReadAsStringAsync();

        Console.WriteLine($"Status: {createResponse.StatusCode}");
        Console.WriteLine(responseBody);

        if (!createResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("❌ Client NOT created");
            return;
        }

        Console.WriteLine("✓ Client created successfully");
        File.Delete(args[0]);
    }

    static string GenerateTOTP(string base32)
    {
        byte[] key = Base32Decode(base32);
        long timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        byte[] data = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(timestep));

        using var hmac = new HMACSHA1(key);
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
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        string bits = "";

        foreach (char c in input.Trim('=').ToUpper())
            bits += Convert.ToString(chars.IndexOf(c), 2).PadLeft(5, '0');

        byte[] result = new byte[bits.Length / 8];
        for (int i = 0; i < result.Length; i++)
            result[i] = Convert.ToByte(bits.Substring(i * 8, 8), 2);

        return result;
    }
}
