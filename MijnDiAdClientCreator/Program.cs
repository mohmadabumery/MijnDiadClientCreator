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

            // 5. Get cookies
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            string xsrfCookie = "";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
                if (c.Name == "XSRF-TOKEN") xsrfCookie = c.Value;
            }

            Console.WriteLine($"  XSRF cookie: {xsrfCookie.Length} chars");

            // 6. Try to get a valid token by calling /api/address/check with VALID address
            Console.WriteLine("\n[4/6] Getting valid token via address check...");
            
            // Use a VALID Dutch address for the check
            var validAddressData = new { 
                zipcode = "1234AB",  // Valid Dutch format
                house_number = "1" 
            };
            
            var addressContent = new StringContent(JsonSerializer.Serialize(validAddressData), Encoding.UTF8, "application/json");
            
            // Build proper cookie header
            string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfCookie}";
            
            // Try multiple approaches to get the correct token
            string[] potentialTokens = new string[3];
            
            // Approach 1: Call address check with valid address
            var addressRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/address/check")
            {
                Content = addressContent
            };
            
            addressRequest.Headers.Add("x-csrf-token", xsrfCookie); // Use cookie value in header
            addressRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            addressRequest.Headers.Add("Origin", baseUrl);
            addressRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            addressRequest.Headers.Add("Cookie", cookieHeader);
            addressRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            addressRequest.Headers.Add("Accept-Language", "nl");

            var addressResponse = await client.SendAsync(addressRequest);
            
            // Check Set-Cookie for new token
            if (addressResponse.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                {
                    if (setCookie.Contains("XSRF-TOKEN="))
                    {
                        var match = Regex.Match(setCookie, @"XSRF-TOKEN=([^;]+)");
                        if (match.Success)
                        {
                            potentialTokens[0] = match.Groups[1].Value;
                            Console.WriteLine($"  Token from address check: {potentialTokens[0]?.Length ?? 0} chars");
                        }
                    }
                }
            }

            // Approach 2: Try to URL-decode the cookie
            try
            {
                potentialTokens[1] = Uri.UnescapeDataString(xsrfCookie);
                Console.WriteLine($"  URL-decoded cookie: {potentialTokens[1]?.Length ?? 0} chars");
            }
            catch { }

            // Approach 3: Use the raw cookie value
            potentialTokens[2] = xsrfCookie;

            // 7. Prepare form data
            Console.WriteLine("\n[5/6] Preparing form data...");
            var formData = BuildFormData(clientJson);

            // 8. Try each potential token
            Console.WriteLine("\n[6/6] Creating client...");
            
            for (int i = 0; i < potentialTokens.Length; i++)
            {
                if (string.IsNullOrEmpty(potentialTokens[i])) continue;
                
                Console.WriteLine($"\n  Attempt {i+1}: Token length {potentialTokens[i].Length} chars...");
                
                var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
                {
                    Content = formData
                };

                // IMPORTANT: The cookie should have the ORIGINAL encoded token
                // The header should have whatever token format works
                clientRequest.Headers.Add("x-csrf-token", potentialTokens[i]);
                clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
                clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
                clientRequest.Headers.Add("Origin", baseUrl);
                clientRequest.Headers.Add("Cookie", cookieHeader); // Keep original encoded token in cookie
                clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
                clientRequest.Headers.Add("Accept-Language", "nl");

                var response = await client.SendAsync(clientRequest);
                var responseBody = await response.Content.ReadAsStringAsync();
                
                Console.WriteLine($"    Status: {response.StatusCode}");
                
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"\n✅✅✅ SUCCESS! Client created ✅✅✅");
                    Console.WriteLine($"Response: {responseBody}");
                    return;
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    Console.WriteLine($"    401 Unauthorized - wrong token format");
                }
                else if (response.StatusCode == HttpStatusCode.UnprocessableEntity)
                {
                    try
                    {
                        var json = JsonSerializer.Deserialize<JsonElement>(responseBody);
                        if (json.TryGetProperty("messages", out var messages))
                        {
                            Console.WriteLine($"    Error: {messages[0]}");
                        }
                    }
                    catch { }
                }
            }
            
            Console.WriteLine("\n❌ All token attempts failed");
            Console.WriteLine("\n=== FINAL DEBUG ===");
            Console.WriteLine($"Original XSRF cookie (first 50 chars): {xsrfCookie.Substring(0, Math.Min(50, xsrfCookie.Length))}...");
            Console.WriteLine($"Session cookie exists: {!string.IsNullOrEmpty(sessionCookie)}");
            Console.WriteLine($"Device token: {deviceToken}");
            Environment.Exit(1);
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
