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
                AutomaticDecompression = DecompressionMethods.All,
                AllowAutoRedirect = false
            };

            using var client = new HttpClient(handler);
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36");

            // 1. Login
            Console.WriteLine("\n[1/4] Logging in...");
            var loginCsrf = await GetLoginCsrfToken(client, baseUrl);
            
            var loginData = new { email = username, password = password, totp_code = totp };
            var loginContent = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");
            
            var loginRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/login")
            {
                Content = loginContent
            };
            loginRequest.Headers.Add("X-CSRF-TOKEN", loginCsrf);
            loginRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            
            var loginResponse = await client.SendAsync(loginRequest);
            if (!loginResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Login failed: {loginResponse.StatusCode}");
                return false;
            }
            Console.WriteLine("  ✓ Login successful");

            // 2. Setup session
            Console.WriteLine("\n[2/4] Setting up session...");
            await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
            cookieContainer.Add(new Uri(baseUrl), new Cookie("locale", "nl"));
            
            // Load the form page to get a FRESH CSRF token
            Console.WriteLine("  Loading form page for fresh CSRF token...");
            var formPage = await client.GetAsync($"{baseUrl}/clients/create");
            var formHtml = await formPage.Content.ReadAsStringAsync();
            
            // Extract the FRESH CSRF token from the form page HTML
            var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!formCsrfMatch.Success)
            {
                Console.WriteLine("❌ No CSRF token in form page");
                return false;
            }
            
            var freshCsrfToken = formCsrfMatch.Groups[1].Value;
            Console.WriteLine($"  Fresh CSRF token: {freshCsrfToken.Length} chars");

            // 3. Get session cookies
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
            }

            // Update cookie with the fresh token
            cookieContainer.Add(uri, new Cookie("XSRF-TOKEN", freshCsrfToken));

            // 4. Prepare MINIMAL form data (only mandatory fields + what's in JSON)
            Console.WriteLine("\n[3/4] Preparing form data...");
            var formData = BuildMinimalFormData(clientJson);

            // 5. Create client with FRESH token
            Console.WriteLine("\n[4/4] Creating client...");
            string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={freshCsrfToken}";
            
            var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            clientRequest.Headers.Add("x-csrf-token", freshCsrfToken);
            clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            clientRequest.Headers.Add("Origin", baseUrl);
            clientRequest.Headers.Add("Cookie", cookieHeader);
            clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            clientRequest.Headers.Add("Accept-Language", "nl");

            Console.WriteLine($"  Using fresh CSRF token from form page");

            var response = await client.SendAsync(clientRequest);
            var responseBody = await response.Content.ReadAsStringAsync();
            
            Console.WriteLine($"\n=== RESPONSE ===");
            Console.WriteLine($"Status: {response.StatusCode}");
            
            if (!string.IsNullOrEmpty(responseBody))
            {
                try
                {
                    var json = JsonSerializer.Deserialize<JsonElement>(responseBody);
                    Console.WriteLine(JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true }));
                }
                catch
                {
                    Console.WriteLine(responseBody);
                }
            }

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd ✅✅✅");
                return true;
            }
            else
            {
                Console.WriteLine($"\n❌ Client creation failed: {response.StatusCode}");
                
                // Debug: Show what we sent
                Console.WriteLine("\n=== DEBUG INFO ===");
                Console.WriteLine($"CSRF Token: {freshCsrfToken}");
                Console.WriteLine($"Session cookie length: {sessionCookie?.Length ?? 0}");
                Console.WriteLine($"Form data fields: {formData.Count()}");
                
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

    static MultipartFormDataContent BuildMinimalFormData(string json)
    {
        var formData = new MultipartFormDataContent();
        var data = JsonSerializer.Deserialize<JsonElement>(json);
        
        // Extract only the fields we need
        var fieldMappings = new Dictionary<string, string>
        {
            { "salutation", "salutation" },
            { "firstname", "firstname" },
            { "lastname", "lastname" },        // MANDATORY
            { "gender", "gender" },
            { "date_of_birth", "date_of_birth" },
            { "date_of_intake", "date_of_intake" },
            { "email", "email" },              // MANDATORY
            { "mobilenumber", "mobilenumber" },
            { "reminder", "reminder" },
            { "confirmation", "confirmation" },
            { "invoice_relation_id", "invoice_relation_id" },  // MANDATORY
            { "invoice_send_method", "invoice_send_method" },
            { "is_active", "is_active" },
            { "different_post_address", "different_post_address" },
            { "allow_dubble_email", "allow_dubble_email" }
        };

        foreach (var mapping in fieldMappings)
        {
            if (data.TryGetProperty(mapping.Key, out var value))
            {
                string stringValue = GetStringValue(value);
                formData.Add(new StringContent(stringValue), mapping.Value);
            }
            else
            {
                // Add empty value for optional fields
                formData.Add(new StringContent(""), mapping.Value);
            }
        }

        // Handle nested objects
        if (data.TryGetProperty("address", out var address))
        {
            AddNestedObject(formData, address, "address");
        }
        else
        {
            // Add empty address fields
            formData.Add(new StringContent(""), "address[country]");
            formData.Add(new StringContent(""), "address[zipcode]");
            formData.Add(new StringContent(""), "address[house_number]");
            formData.Add(new StringContent(""), "address[street]");
            formData.Add(new StringContent(""), "address[city]");
        }

        if (data.TryGetProperty("invoice_address", out var invoiceAddress))
        {
            AddNestedObject(formData, invoiceAddress, "invoice_address");
        }

        // Add empty arrays
        formData.Add(new StringContent(""), "client_attributes[]");
        formData.Add(new StringContent(""), "client_group_ids");

        return formData;
    }

    static void AddNestedObject(MultipartFormDataContent formData, JsonElement element, string prefix)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in element.EnumerateObject())
            {
                string key = $"{prefix}[{prop.Name}]";
                string value = GetStringValue(prop.Value);
                formData.Add(new StringContent(value), key);
            }
        }
    }

    static string GetStringValue(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? "",
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "1",
            JsonValueKind.False => "0",
            JsonValueKind.Null => "",
            _ => element.ToString()
        };
    }

    static async Task<string> GetLoginCsrfToken(HttpClient client, string baseUrl)
    {
        var loginPage = await client.GetAsync($"{baseUrl}/login");
        var loginHtml = await loginPage.Content.ReadAsStringAsync();
        var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
        
        if (!csrfMatch.Success)
        {
            throw new Exception("CSRF token not found in login page");
        }
        
        return csrfMatch.Groups[1].Value;
    }

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
