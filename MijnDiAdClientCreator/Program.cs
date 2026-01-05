using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.IO;
using OtpNet;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== MijnDiAd Client Creator ===");

        string jsonPath = "client_data.json";
        if (!File.Exists(jsonPath))
        {
            Console.WriteLine("❌ client_data.json not found");
            Environment.Exit(1);
        }

        string clientJson = await File.ReadAllTextAsync(jsonPath);

        // Validate JSON early
        JsonSerializer.Deserialize<JsonElement>(clientJson);

        string tenant = Env("MIJNDIAD_TENANT");
        string username = Env("MIJNDIAD_USERNAME");
        string password = Env("MIJNDIAD_PASSWORD");
        string totpSecret = Env("MIJNDIAD_TOTP_SECRET");

        string baseUrl = $"https://{tenant}.mijndiad.nl";
        Console.WriteLine($"Target: {baseUrl}");

        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookies,
            UseCookies = true,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        );

        // 1️⃣ LOGIN (JSON, SAME AS BEFORE)
        Console.WriteLine("[1/6] Logging in...");
        await Login(client, baseUrl, username, password, totpSecret);
        Console.WriteLine("✓ Login successful");

        // 2️⃣ SANCTUM
        Console.WriteLine("[2/6] Initializing Sanctum...");
        await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");

        // 3️⃣ LOAD CREATE FORM (FRESH CSRF)
        Console.WriteLine("[3/6] Loading create form...");
        var formPage = await client.GetAsync($"{baseUrl}/clients/create");
        var html = await formPage.Content.ReadAsStringAsync();

        var csrfMatch = Regex.Match(
            html,
            "<meta name=\"csrf-token\" content=\"([^\"]+)\""
        );

        if (!csrfMatch.Success)
            throw new Exception("Fresh CSRF token not found");

        string csrfToken = csrfMatch.Groups[1].Value;
        Console.WriteLine($"✓ Fresh CSRF token ({csrfToken.Length} chars)");

        // 4️⃣ BIND API SESSION
        Console.WriteLine("[4/6] Binding API session...");
        var userCheck = await client.GetAsync($"{baseUrl}/api/user");
        if (!userCheck.IsSuccessStatusCode)
            throw new Exception("API session binding failed");
        Console.WriteLine("✓ API session bound");

        // 5️⃣ PREPARE PAYLOAD
        Console.WriteLine("[5/6] Preparing payload...");
        var jsonContent = new StringContent(
            clientJson,
            Encoding.UTF8,
            "application/json"
        );

        // 6️⃣ CREATE CLIENT
        Console.WriteLine("[6/6] Creating client...");
        var createReq = new HttpRequestMessage(
            HttpMethod.Post,
            $"{baseUrl}/api/clients"
        );
        createReq.Content = jsonContent;
        createReq.Headers.Add("X-CSRF-TOKEN", csrfToken);
        createReq.Headers.Add("X-Requested-With", "XMLHttpRequest");
        createReq.Headers.Add("Accept", "application/json");
        createReq.Headers.Referrer = new Uri($"{baseUrl}/clients/create");

        var response = await client.SendAsync(createReq);
        var body = await response.Content.ReadAsStringAsync();

        Console.WriteLine($"Status: {response.StatusCode}");
        Console.WriteLine(body);

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine("❌ Client creation failed");
            Environment.Exit(1);
        }

        Console.WriteLine("✅ Client successfully created");
    }

    // ===== LOGIN (DO NOT TOUCH) =====
    static async Task Login(
        HttpClient client,
        string baseUrl,
        string username,
        string password,
        string totpSecret
    )
    {
        var loginPage = await client.GetAsync($"{baseUrl}/login");
        var html = await loginPage.Content.ReadAsStringAsync();

        var csrfMatch = Regex.Match(
            html,
            "<meta name=\"csrf-token\" content=\"([^\"]+)\""
        );

        if (!csrfMatch.Success)
            throw new Exception("Login CSRF not found");

        string csrf = csrfMatch.Groups[1].Value;

        var payload = new
        {
            email = username,
            password = password,
            totp_code = GenerateTotp(totpSecret)
        };

        var req = new HttpRequestMessage(
            HttpMethod.Post,
            $"{baseUrl}/api/login"
        );
        req.Content = new StringContent(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8,
            "application/json"
        );
        req.Headers.Add("X-CSRF-TOKEN", csrf);
        req.Headers.Add("X-Requested-With", "XMLHttpRequest");

        var res = await client.SendAsync(req);

        if (!res.IsSuccessStatusCode)
        {
            var body = await res.Content.ReadAsStringAsync();
            throw new Exception($"Login failed: {res.StatusCode}\n{body}");
        }
    }

    static string GenerateTotp(string secret)
    {
        var bytes = Base32Encoding.ToBytes(secret);
        var totp = new Totp(bytes);
        return totp.ComputeTotp();
    }

    static string Env(string name)
    {
        var v = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrEmpty(v))
            throw new Exception($"Missing env var: {name}");
        return v;
    }
}
