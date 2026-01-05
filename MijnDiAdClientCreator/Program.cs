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
            Console.WriteLine($"❌ JSON file not found: {jsonFilePath}");
            Environment.Exit(1);
        }

        string clientJson = await File.ReadAllTextAsync(jsonFilePath);
        Console.WriteLine($"Read JSON from {jsonFilePath} ({clientJson.Length} chars)");

        try
        {
            JsonSerializer.Deserialize<JsonElement>(clientJson);
            Console.WriteLine("✓ JSON is valid");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Invalid JSON: {ex.Message}");
            Environment.Exit(1);
        }

        bool success = await CreateClient(clientJson);
        Environment.Exit(success ? 0 : 1);
    }

    static async Task<bool> CreateClient(string clientJson)
    {
        try
        {
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

            if (string.IsNullOrWhiteSpace(tenant) ||
                string.IsNullOrWhiteSpace(username) ||
                string.IsNullOrWhiteSpace(password) ||
                string.IsNullOrWhiteSpace(totpSecret))
            {
                Console.WriteLine("❌ Missing environment variables");
                return false;
            }

            string baseUrl = $"https://{tenant}.mijndiad.nl";
            string totp = GenerateTotp(totpSecret);

            Console.WriteLine($"\nTarget: {baseUrl}");

            var cookieContainer = new CookieContainer();
            var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.All
            };

            using var client = new HttpClient(handler);
            client.DefaultRequestHeaders.Add("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

            // ------------------------------------------------------------
            // [1] LOGIN
            // ------------------------------------------------------------
            Console.WriteLine("\n[1/6] Logging in...");

            string loginCsrf = await GetCsrfFromPage(client, $"{baseUrl}/login");

            var loginPayload = new
            {
                email = username,
                password = password,
                totp_code = totp
            };

            var loginRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/login");
            loginRequest.Content = new StringContent(
                JsonSerializer.Serialize(loginPayload),
                Encoding.UTF8,
                "application/json");

            loginRequest.Headers.Add("X-CSRF-TOKEN", loginCsrf);
            loginRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");

            var loginResponse = await client.SendAsync(loginRequest);
            if (!loginResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Login failed: {loginResponse.StatusCode}");
                return false;
            }

            Console.WriteLine("  ✓ Login successful");

            // ------------------------------------------------------------
            // [2] SANCTUM CSRF
            // ------------------------------------------------------------
            Console.WriteLine("\n[2/6] Initializing Sanctum...");
            await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");

            // ------------------------------------------------------------
            // [3] LOAD FORM + FRESH CSRF
            // ------------------------------------------------------------
            Console.WriteLine("\n[3/6] Loading create form...");
            string freshCsrf = await GetCsrfFromPage(client, $"{baseUrl}/clients/create");
            Console.WriteLine($"  ✓ Fresh CSRF token ({freshCsrf.Length} chars)");

            // ------------------------------------------------------------
            // [4] BIND SESSION TO API (CRITICAL FIX)
            // ------------------------------------------------------------
            Console.WriteLine("\n[4/6] Binding session to API...");

            var apiUserRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/user");
            apiUserRequest.Headers.Add("X-CSRF-TOKEN", freshCsrf);
            apiUserRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            apiUserRequest.Headers.Add("Referer", $"{baseUrl}/clients");
            apiUserRequest.Headers.Add("Accept", "application/json");

            var apiUserResponse = await client.SendAsync(apiUserRequest);
            if (!apiUserResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("❌ API session binding failed");
                Console.WriteLine(await apiUserResponse.Content.ReadAsStringAsync());
                return false;
            }

            Console.WriteLine("  ✓ API session bound");

            // ------------------------------------------------------------
            // [5] BUILD FORM DATA
            // ------------------------------------------------------------
            Console.WriteLine("\n[5/6] Preparing client payload...");
            var formData = BuildFormData(clientJson);

            // ------------------------------------------------------------
            // [6] CREATE CLIENT
            // ------------------------------------------------------------
            Console.WriteLine("\n[6/6] Creating client...");

            var createRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients");
            createRequest.Content = formData;
            createRequest.Headers.Add("X-CSRF-TOKEN", freshCsrf);
            createRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            createRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            createRequest.Headers.Add("Origin", baseUrl);
            createRequest.Headers.Add("Accept", "application/json");

            var response = await client.SendAsync(createRequest);
            var body = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"\nStatus: {response.StatusCode}");
            Console.WriteLine(body);

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("\n✅ CLIENT CREATED SUCCESSFULLY");
                return true;
            }

            Console.WriteLine("\n❌ Client creation failed");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine("\n❌ Unexpected error:");
            Console.WriteLine(ex);
            return false;
        }
    }

    // ================================================================
    // HELPERS
    // ================================================================
    static async Task<string> GetCsrfFromPage(HttpClient client, string url)
    {
        var response = await client.GetAsync(url);
        var html = await response.Content.ReadAsStringAsync();

        var match = Regex.Match(html, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        if (!match.Success)
            throw new Exception("CSRF token not found");

        return match.Groups[1].Value;
    }

    static MultipartFormDataContent BuildFormData(string json)
    {
        var data = JsonSerializer.Deserialize<JsonElement>(json);
        var form = new MultipartFormDataContent();

        void Add(string key, string value) =>
            form.Add(new StringContent(value ?? ""), key);

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

        Add("client_attributes[]", "");
        Add("client_group_ids", "");

        return form;
    }

    static string GenerateTotp(string base32Secret)
    {
        var secret = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(secret);
        return totp.ComputeTotp();
    }
}
