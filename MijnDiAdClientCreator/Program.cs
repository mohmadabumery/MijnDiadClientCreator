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
            var testParse = JsonSerializer.Deserialize<JsonElement>(clientJson);
            Console.WriteLine("✓ JSON is valid");
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"❌ Invalid JSON: {ex.Message}");
            Environment.Exit(1);
        }

        bool success = await CreateClient(clientJson);

        if (!success)
        {
            Environment.Exit(1);
        }
    }

    static async Task<bool> CreateClient(string clientJson)
    {
        try
        {
            var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
            var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

            if (string.IsNullOrEmpty(tenant) || string.IsNullOrEmpty(username) ||
                string.IsNullOrEmpty(password) || string.IsNullOrEmpty(totpSecret))
            {
                Console.WriteLine("❌ Missing environment variables");
                return false;
            }

            var totp = GenerateTotp(totpSecret);
            var baseUrl = $"https://{tenant}.mijndiad.nl";

            Console.WriteLine($"\nTarget: {baseUrl}");

            var cookieContainer = new CookieContainer();
            var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true,
                AutomaticDecompression = DecompressionMethods.All
            };

            using var client = new HttpClient(handler);
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36");

            // 1. Login
            Console.WriteLine("\n[1/5] Logging in...");
            bool loginSuccess = await Login(client, baseUrl, username, password, totp);
            if (!loginSuccess)
            {
                Console.WriteLine("❌ Login failed");
                return false;
            }
            Console.WriteLine("  ✓ Login successful");

            // 2. Initialize Sanctum
            Console.WriteLine("\n[2/5] Initializing Sanctum...");
            await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");

            // 3. Load /clients/create to get fresh CSRF
            Console.WriteLine("\n[3/5] Loading create form...");
            var formPage = await client.GetAsync($"{baseUrl}/clients/create");
            var formHtml = await formPage.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!csrfMatch.Success)
            {
                Console.WriteLine("❌ Could not find CSRF token on create page");
                return false;
            }
            string csrfToken = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  ✓ Fresh CSRF token ({csrfToken.Length} chars)");

            // 4. Bind API session
            Console.WriteLine("\n[4/5] Binding API session...");
            var bindResponse = await client.GetAsync($"{baseUrl}/api/user");
            if (!bindResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Failed to bind API session: {bindResponse.StatusCode}");
                return false;
            }
            Console.WriteLine("  ✓ API session bound");

            // 5. Create client
            Console.WriteLine("\n[5/5] Creating client...");
            var formData = BuildMultipartFormData(clientJson);

            var createRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };
            createRequest.Headers.Add("X-CSRF-TOKEN", csrfToken);
            createRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            createRequest.Headers.Add("Accept", "application/json, text/plain, */*");

            var response = await client.SendAsync(createRequest);
            var responseBody = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"\n=== RESPONSE ===");
            Console.WriteLine($"Status: {response.StatusCode}");
            Console.WriteLine(responseBody);

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd ✅✅✅");
                return true;
            }
            else
            {
                Console.WriteLine("\n❌ Client creation failed");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ Unexpected error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            return false;
        }
    }

    static async Task<bool> Login(HttpClient client, string baseUrl, string username, string password, string totp)
    {
        var loginData = new { email = username, password = password, totp_code = totp };
        var loginContent = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");

        var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/login")
        {
            Content = loginContent
        };
        request.Headers.Add("X-Requested-With", "XMLHttpRequest");
        request.Headers.Add("Accept", "application/json, text/plain, */*");

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Console.WriteLine($"Login Status: {response.StatusCode}");
        Console.WriteLine(body);

        return response.IsSuccessStatusCode;
    }

    static MultipartFormDataContent BuildMultipartFormData(string json)
    {
        var formData = new MultipartFormDataContent();
        var data = JsonSerializer.Deserialize<JsonElement>(json);

        foreach (var prop in data.EnumerateObject())
        {
            if (prop.Value.ValueKind == JsonValueKind.Object || prop.Value.ValueKind == JsonValueKind.Array)
            {
                formData.Add(new StringContent(prop.Value.GetRawText()), prop.Name);
            }
            else
            {
                formData.Add(new StringContent(GetStringValue(prop.Value)), prop.Name);
            }
        }

        return formData;
    }

    static string GetStringValue(JsonElement element) =>
        element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? "",
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "1",
            JsonValueKind.False => "0",
            JsonValueKind.Null => "",
            _ => element.ToString()
        };

    static string GenerateTotp(string base32Secret)
    {
        if (string.IsNullOrEmpty(base32Secret)) return "000000";
        try
        {
            var secretKey = Base32Encoding.ToBytes(base32Secret);
            var totp = new Totp(secretKey);
            return totp.ComputeTotp();
        }
        catch
        {
            return "123456";
        }
    }
}
