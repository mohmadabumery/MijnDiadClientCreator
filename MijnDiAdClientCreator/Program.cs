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
        
        // Check if JSON file exists
        if (!File.Exists(jsonFilePath))
        {
            Console.WriteLine($"❌ JSON file not found: {jsonFilePath}");
            Console.WriteLine("Please provide a JSON file or use: dotnet run -- --json-file path/to/file.json");
            Environment.Exit(1);
        }
        
        // Read and validate JSON
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

        // Run the client creation
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
                Console.WriteLine("❌ Missing environment variables. Check your GitHub Secrets.");
                Console.WriteLine("Required: MIJNDIAD_TENANT, MIJNDIAD_USERNAME, MIJNDIAD_PASSWORD, MIJNDIAD_TOTP_SECRET");
                return false;
            }

            var totp = GenerateTotp(totpSecret);
            var baseUrl = $"https://{tenant}.mijndiad.nl";

            Console.WriteLine($"\nTarget: {baseUrl}");
            Console.WriteLine($"User: {username}");

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
            await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
            cookieContainer.Add(new Uri(baseUrl), new Cookie("locale", "nl"));
            await client.GetAsync($"{baseUrl}/clients/create");

            // 3. Get cookies
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            string jwtXsrfToken = "";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
                if (c.Name == "XSRF-TOKEN") jwtXsrfToken = c.Value;
            }

            // 4. Get valid token via address check
            Console.WriteLine("\n[2/4] Getting valid CSRF token...");
            string plainXsrfToken = await GetValidCsrfToken(client, baseUrl, tenant, clientJson, 
                sessionCookie, deviceToken, mdsbCookie, jwtXsrfToken);

            if (string.IsNullOrEmpty(plainXsrfToken))
            {
                Console.WriteLine("❌ Could not obtain valid CSRF token");
                return false;
            }

            // 5. Prepare form data
            Console.WriteLine("\n[3/4] Preparing client data...");
            var formData = BuildFormData(clientJson);

            // 6. Create client
            Console.WriteLine("\n[4/4] Creating client...");
            string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={plainXsrfToken}";
            
            var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            clientRequest.Headers.Add("x-csrf-token", plainXsrfToken);
            clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            clientRequest.Headers.Add("Origin", baseUrl);
            clientRequest.Headers.Add("Cookie", cookieHeader);
            clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            clientRequest.Headers.Add("Accept-Language", "nl");

            Console.WriteLine($"  Using token: {plainXsrfToken.Substring(0, Math.Min(10, plainXsrfToken.Length))}...");

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
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ Unexpected error: {ex.Message}");
            return false;
        }
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

    static async Task<string> GetValidCsrfToken(HttpClient client, string baseUrl, string tenant, 
        string clientJson, string sessionCookie, string deviceToken, string mdsbCookie, string jwtXsrfToken)
    {
        var uri = new Uri(baseUrl);
        
        // Try to extract address from JSON
        string zipcode = "";
        string houseNumber = "";
        
        try
        {
            var clientData = JsonSerializer.Deserialize<JsonElement>(clientJson);
            if (clientData.TryGetProperty("address", out var address))
            {
                if (address.TryGetProperty("zipcode", out var zip) && !string.IsNullOrEmpty(zip.GetString()))
                    zipcode = zip.GetString();
                if (address.TryGetProperty("house_number", out var house) && !string.IsNullOrEmpty(house.GetString()))
                    houseNumber = house.GetString();
            }
        }
        catch { }

        // If no valid address in JSON, use a default valid one
        if (string.IsNullOrEmpty(zipcode) || !IsValidDutchZipcode(zipcode))
        {
            Console.WriteLine($"  Using default valid address (provided: {zipcode})");
            zipcode = "1011AA";
            houseNumber = "1";
        }

        // Build cookie header
        string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={jwtXsrfToken}";
        
        var addressCheckData = new { 
            zipcode = zipcode,
            house_number = houseNumber 
        };
        
        var addressContent = new StringContent(JsonSerializer.Serialize(addressCheckData), Encoding.UTF8, "application/json");
        
        var addressRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/address/check")
        {
            Content = addressContent
        };
        
        addressRequest.Headers.Add("x-csrf-token", jwtXsrfToken);
        addressRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
        addressRequest.Headers.Add("Origin", baseUrl);
        addressRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
        addressRequest.Headers.Add("Cookie", cookieHeader);
        addressRequest.Headers.Add("Accept", "application/json, text/plain, */*");
        addressRequest.Headers.Add("Accept-Language", "nl");

        var addressResponse = await client.SendAsync(addressRequest);
        
        if (addressResponse.StatusCode == HttpStatusCode.OK)
        {
            Console.WriteLine($"  ✓ Address check successful");
            
            // Extract token from Set-Cookie
            if (addressResponse.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                {
                    if (setCookie.Contains("XSRF-TOKEN="))
                    {
                        var match = Regex.Match(setCookie, @"XSRF-TOKEN=([^;]+)");
                        if (match.Success)
                        {
                            var token = match.Groups[1].Value;
                            Console.WriteLine($"  Obtained valid CSRF token ({token.Length} chars)");
                            
                            // Update cookie container
                            cookieContainer.Add(uri, new Cookie("XSRF-TOKEN", token));
                            return token;
                        }
                    }
                }
            }
        }
        else
        {
            Console.WriteLine($"  ⚠️ Address check failed: {addressResponse.StatusCode}");
            Console.WriteLine($"  Using JWT token as fallback");
            return jwtXsrfToken;
        }
        
        return jwtXsrfToken; // Fallback
    }

    static bool IsValidDutchZipcode(string zipcode)
    {
        // Basic Dutch zipcode validation: 4 digits + 2 letters (e.g., 1234AB)
        if (string.IsNullOrEmpty(zipcode) || zipcode.Length != 6)
            return false;
            
        var digits = zipcode.Substring(0, 4);
        var letters = zipcode.Substring(4, 2);
        
        return digits.All(char.IsDigit) && letters.All(char.IsLetter);
    }

    static CookieContainer cookieContainer = new CookieContainer();

    static MultipartFormDataContent BuildFormData(string json)
    {
        var formData = new MultipartFormDataContent();
        var data = JsonSerializer.Deserialize<JsonElement>(json);
        
        AddToFormData(formData, data, "");
        return formData;
    }

    static void AddToFormData(MultipartFormDataContent formData, JsonElement element, string prefix)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    string key = string.IsNullOrEmpty(prefix) ? prop.Name : $"{prefix}[{prop.Name}]";
                    AddToFormData(formData, prop.Value, key);
                }
                break;
                
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    AddToFormData(formData, item, $"{prefix}[]");
                }
                if (!element.EnumerateArray().Any())
                {
                    formData.Add(new StringContent(""), $"{prefix}[]");
                }
                break;
                
            default:
                string value = element.ValueKind switch
                {
                    JsonValueKind.String => element.GetString() ?? "",
                    JsonValueKind.Number => element.GetRawText(),
                    JsonValueKind.True => "1",
                    JsonValueKind.False => "0",
                    _ => ""
                };
                formData.Add(new StringContent(value), prefix);
                break;
        }
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
