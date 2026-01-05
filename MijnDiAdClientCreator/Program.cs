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

        string jsonFilePath = args.Length > 0 && args[0].StartsWith("--json-file")
            ? args[1]
            : "client_data.json";

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
        catch (JsonException ex)
        {
            Console.WriteLine($"❌ Invalid JSON: {ex.Message}");
            Environment.Exit(1);
        }

        bool success = await CreateClient(clientJson);
        if (!success) Environment.Exit(1);
    }

    static async Task<bool> CreateClient(string clientJson)
    {
        try
        {
            // 1️⃣ Environment variables
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

            Console.WriteLine($"Target: {baseUrl}");

            var cookieContainer = new CookieContainer();
            var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true,
                AutomaticDecompression = DecompressionMethods.All,
                AllowAutoRedirect = true
            };

            using var client = new HttpClient(handler);
            client.DefaultRequestHeaders.Add("User-Agent", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36");

            // 2️⃣ Login
            Console.WriteLine("\n[1/5] Logging in...");
            bool loginSuccess = await Login(client, baseUrl, username, password, totp);
            if (!loginSuccess)
            {
                Console.WriteLine("❌ Login failed");
                return false;
            }
            Console.WriteLine("✓ Login successful");

            // 3️⃣ Initialize Sanctum / CSRF
            Console.WriteLine("\n[2/5] Initializing Sanctum...");
            await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");

            // 4️⃣ Load /clients/create for fresh CSRF
            Console.WriteLine("\n[3/5] Loading create form for CSRF...");
            var formResponse = await client.GetAsync($"{baseUrl}/clients/create");
            var formHtml = await formResponse.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!csrfMatch.Success)
            {
                Console.WriteLine("❌ Could not extract CSRF token from form page");
                return false;
            }
            var freshCsrfToken = csrfMatch.Groups[1].Value;
            Console.WriteLine($"✓ Fresh CSRF token: {freshCsrfToken.Length} chars");

            // 5️⃣ Bind API session
            Console.WriteLine("\n[4/5] Binding API session...");
            var bindResp = await client.GetAsync($"{baseUrl}/api/user");
            if (!bindResp.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Failed to bind API session: {bindResp.StatusCode}");
                return false;
            }
            Console.WriteLine("✓ API session bound");

            // 6️⃣ Create client
            Console.WriteLine("\n[5/5] Creating client...");
            var multipartContent = BuildMultipartFormData(clientJson);
            var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = multipartContent
            };
            request.Headers.Add("X-CSRF-TOKEN", freshCsrfToken);
            request.Headers.Add("X-Requested-With", "XMLHttpRequest");

            var response = await client.SendAsync(request);
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
            return false;
        }
    }

    static async Task<bool> Login(HttpClient client, string baseUrl, string username, string password, string totp)
    {
        var loginData = new
        {
            email = username,
            password = password,
            totp_code = totp
        };
        var loginContent = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");

        var response = await client.PostAsync($"{baseUrl}/api/login", loginContent);
        return response.IsSuccessStatusCode;
    }

    static MultipartFormDataContent BuildMultipartFormData(string json)
    {
        var formData = new MultipartFormDataContent();
        var data = JsonSerializer.Deserialize<JsonElement>(json);

        void AddField(string name, string value) => formData.Add(new StringContent(value ?? ""), name);

        // Required / optional fields
        AddField("salutation", GetValue(data, "salutation"));
        AddField("initials", GetValue(data, "initials"));
        AddField("firstname", GetValue(data, "firstname"));
        AddField("lastname", GetValue(data, "lastname"));
        AddField("gender", GetValue(data, "gender"));
        AddField("nationality", GetValue(data, "nationality"));
        AddField("date_of_intake", GetValue(data, "date_of_intake"));
        AddField("email", GetValue(data, "email"));
        AddField("mobilenumber", GetValue(data, "mobilenumber"));
        AddField("reminder", GetValue(data, "reminder"));
        AddField("confirmation", GetValue(data, "confirmation"));
        AddField("invoice_relation_id", GetValue(data, "invoice_relation_id"));
        AddField("invoice_send_method", GetValue(data, "invoice_send_method"));
        AddField("is_active", GetValue(data, "is_active"));
        AddField("address", JsonSerializer.Serialize(data.GetProperty("address")));
        AddField("invoice_address", JsonSerializer.Serialize(data.GetProperty("invoice_address")));
        AddField("different_post_address", GetValue(data, "different_post_address"));
        AddField("client_attributes", "[]");
        AddField("client_group_ids", "null");
        AddField("allow_dubble_email", GetValue(data, "allow_dubble_email"));

        return formData;
    }

    static string GetValue(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) ? v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetRawText(),
            JsonValueKind.True => "1",
            JsonValueKind.False => "0",
            _ => ""
        } : "";

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
