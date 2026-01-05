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
        string clientJson = args.Length >= 2 && args[0] == "--json-file" 
            ? await File.ReadAllTextAsync(args[1])
            : await File.ReadAllTextAsync("client_data.json");

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
        var totp = GenerateTotp(totpSecret);

        var baseUrl = $"https://{tenant}.mijndiad.nl";

        Console.WriteLine("== MijnDiAd Client Creation ==");

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

        try
        {
            // 1. GET login page
            Console.WriteLine("\n[1/6] Getting login page...");
            var loginPage = await client.GetAsync($"{baseUrl}/login");
            var loginHtml = await loginPage.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var loginCsrf = csrfMatch.Groups[1].Value;

            // 2. Login
            Console.WriteLine("\n[2/6] Logging in...");
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
                return;
            }
            Console.WriteLine("  ✓ Login successful");

            // 3. Sanctum + locale
            await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
            cookieContainer.Add(new Uri(baseUrl), new Cookie("locale", "nl"));

            // 4. Load form page
            Console.WriteLine("\n[3/6] Loading form page...");
            await client.GetAsync($"{baseUrl}/clients/create");

            // 5. Get initial cookies (JWT token)
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

            Console.WriteLine($"  JWT XSRF token: {jwtXsrfToken.Length} chars");

            // 6. CRITICAL: Call /api/address/check to get PLAIN token
            Console.WriteLine("\n[4/6] Getting plain token via address check...");
            
            // Use address from JSON
            var clientData = JsonSerializer.Deserialize<JsonElement>(clientJson);
            string zipcode = "1234AB"; // Default valid Dutch zip
            string houseNumber = "1";
            
            if (clientData.TryGetProperty("address", out var address))
            {
                if (address.TryGetProperty("zipcode", out var zip) && !string.IsNullOrEmpty(zip.GetString()))
                    zipcode = zip.GetString() ?? "1234AB";
                if (address.TryGetProperty("house_number", out var house) && !string.IsNullOrEmpty(house.GetString()))
                    houseNumber = house.GetString() ?? "1";
            }

            var addressCheckData = new { 
                zipcode = zipcode,
                house_number = houseNumber 
            };
            
            var addressContent = new StringContent(JsonSerializer.Serialize(addressCheckData), Encoding.UTF8, "application/json");
            
            // Build cookie header with JWT token
            string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={jwtXsrfToken}";
            
            var addressRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/address/check")
            {
                Content = addressContent
            };
            
            addressRequest.Headers.Add("x-csrf-token", jwtXsrfToken); // Use JWT token in header
            addressRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            addressRequest.Headers.Add("Origin", baseUrl);
            addressRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            addressRequest.Headers.Add("Cookie", cookieHeader);
            addressRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            addressRequest.Headers.Add("Accept-Language", "nl");

            var addressResponse = await client.SendAsync(addressRequest);
            var addressBody = await addressResponse.Content.ReadAsStringAsync();
            
            Console.WriteLine($"  Address check: {addressResponse.StatusCode}");
            
            // EXTRACT PLAIN TOKEN from Set-Cookie
            string plainXsrfToken = "";
            if (addressResponse.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                {
                    if (setCookie.Contains("XSRF-TOKEN="))
                    {
                        // Format: XSRF-TOKEN=HeH6pNq3G20z5ItoE7mGhPdaWN0PyxL7yCzhVZF3; path=/; secure; httponly; samesite=none
                        var match = Regex.Match(setCookie, @"XSRF-TOKEN=([^;]+)");
                        if (match.Success)
                        {
                            plainXsrfToken = match.Groups[1].Value;
                            Console.WriteLine($"  Plain token from Set-Cookie: {plainXsrfToken}");
                            Console.WriteLine($"  Token length: {plainXsrfToken.Length} chars");
                            
                            // Update cookie container with PLAIN token (not JWT)
                            cookieContainer.Add(uri, new Cookie("XSRF-TOKEN", plainXsrfToken));
                        }
                    }
                }
            }

            if (string.IsNullOrEmpty(plainXsrfToken))
            {
                Console.WriteLine("❌ No plain token from address check");
                plainXsrfToken = jwtXsrfToken; // Fallback to JWT
            }

            // 7. Prepare form data
            Console.WriteLine("\n[5/6] Preparing form data...");
            var formData = BuildFormData(clientJson);

            // 8. Create client with PLAIN token
            Console.WriteLine("\n[6/6] Creating client with plain token...");
            
            // Update cookie header with PLAIN token
            cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={plainXsrfToken}";
            
            var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            // Use PLAIN token in header (lowercase)
            clientRequest.Headers.Add("x-csrf-token", plainXsrfToken);
            clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            clientRequest.Headers.Add("Origin", baseUrl);
            clientRequest.Headers.Add("Cookie", cookieHeader);
            clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            clientRequest.Headers.Add("Accept-Language", "nl");

            Console.WriteLine($"  Using plain token: {plainXsrfToken}");
            Console.WriteLine($"  Token in cookie: {plainXsrfToken}");

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
                Console.WriteLine("\n✅✅✅ SUCCESS! Client created ✅✅✅");
            }
            else
            {
                Console.WriteLine($"\n❌ Failed: {response.StatusCode}");
                Console.WriteLine($"\n=== DEBUG ===");
                Console.WriteLine($"Plain token used: {plainXsrfToken}");
                Console.WriteLine($"Token length: {plainXsrfToken.Length}");
                Console.WriteLine($"Expected: 40 chars (like HeH6pNq3G20z5ItoE7mGhPdaWN0PyxL7yCzhVZF3)");
                Environment.Exit(1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ Error: {ex.Message}");
            Environment.Exit(1);
        }
    }

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
