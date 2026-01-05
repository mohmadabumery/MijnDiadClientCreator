using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;
using OtpNet;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== MijnDiAd Client Creator ===");

        string jsonFilePath = "client_data.json";
        if (!File.Exists(jsonFilePath))
        {
            Console.WriteLine("❌ client_data.json not found");
            Environment.Exit(1);
        }

        string clientJson = await File.ReadAllTextAsync(jsonFilePath);
        JsonSerializer.Deserialize<JsonElement>(clientJson);

        bool success = await CreateClient(clientJson);
        Environment.Exit(success ? 0 : 1);
    }

    static async Task<bool> CreateClient(string clientJson)
    {
        string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        string baseUrl = $"https://{tenant}.mijndiad.nl";

        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookies,
            UseCookies = true,
            AllowAutoRedirect = false
        };

        using var client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");

        Console.WriteLine("Target: " + baseUrl);

        // -------------------------------------------------
        // LOGIN
        // -------------------------------------------------
        Console.WriteLine("[1/6] Logging in...");
        string loginCsrf = await GetCsrf(client, $"{baseUrl}/login");

        var loginPayload = new
        {
            email = username,
            password = password,
            totp_code = GenerateTotp(totpSecret)
        };

        var loginReq = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/login");
        loginReq.Headers.Add("X-CSRF-TOKEN", loginCsrf);
        loginReq.Headers.Add("X-Requested-With", "XMLHttpRequest");
        loginReq.Content = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");

        var loginResp = await client.SendAsync(loginReq);
        if (!loginResp.IsSuccessStatusCode) return false;

        Console.WriteLine("✓ Login successful");

        // -------------------------------------------------
        // SANCTUM
        // -------------------------------------------------
        Console.WriteLine("[2/6] Initializing Sanctum...");
        await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");

        // -------------------------------------------------
        // FORM PAGE
        // -------------------------------------------------
        Console.WriteLine("[3/6] Loading create form...");
        await client.GetAsync($"{baseUrl}/clients/create");

        // -------------------------------------------------
        // API BIND
        // -------------------------------------------------
        Console.WriteLine("[4/6] Binding API session...");
        var xsrfCookie = cookies.GetCookies(new Uri(baseUrl))["XSRF-TOKEN"]?.Value;
        string decodedXsrf = WebUtility.UrlDecode(xsrfCookie);

        var apiBind = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/user");
        apiBind.Headers.Add("X-XSRF-TOKEN", decodedXsrf);
        apiBind.Headers.Add("X-Requested-With", "XMLHttpRequest");

        var apiResp = await client.SendAsync(apiBind);
        if (!apiResp.IsSuccessStatusCode) return false;

        Console.WriteLine("✓ API session bound");

        // -------------------------------------------------
        // FORM DATA (URL ENCODED)
        // -------------------------------------------------
        Console.WriteLine("[5/6] Preparing payload...");
        var formFields = BuildUrlEncodedForm(clientJson);

        // -------------------------------------------------
        // CREATE CLIENT
        // -------------------------------------------------
        Console.WriteLine("[6/6] Creating client...");

        var createReq = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients");
        createReq.Headers.Add("X-XSRF-TOKEN", decodedXsrf);
        createReq.Headers.Add("X-Requested-With", "XMLHttpRequest");
        createReq.Headers.Add("Accept", "application/json");
        createReq.Content = new FormUrlEncodedContent(formFields);

        var createResp = await client.SendAsync(createReq);
        string body = await createResp.Content.ReadAsStringAsync();

        Console.WriteLine($"Status: {createResp.StatusCode}");
        Console.WriteLine(body);

        return createResp.IsSuccessStatusCode;
    }

    static async Task<string> GetCsrf(HttpClient client, string url)
    {
        var html = await client.GetStringAsync(url);
        var m = Regex.Match(html, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        return m.Groups[1].Value;
    }

    static Dictionary<string, string> BuildUrlEncodedForm(string json)
    {
        var data = JsonSerializer.Deserialize<JsonElement>(json);
        var dict = new Dictionary<string, string>();

        void Add(string k, string v) => dict[k] = v ?? "";

        Add("firstname", data.GetProperty("firstname").GetString());
        Add("lastname", data.GetProperty("lastname").GetString());
        Add("email", data.GetProperty("email").GetString());
        Add("gender", data.GetProperty("gender").GetString());
        Add("invoice_relation_id", data.GetProperty("invoice_relation_id").GetString());

        if (data.TryGetProperty("address", out var addr))
        {
            foreach (var p in addr.EnumerateObject())
                Add($"address[{p.Name}]", p.Value.GetString());
        }

        dict["client_attributes[]"] = "";
        dict["client_group_ids"] = "";

        return dict;
    }

    static string GenerateTotp(string secret)
    {
        var bytes = Base32Encoding.ToBytes(secret);
        return new Totp(bytes).ComputeTotp();
    }
}
