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

            // 5. Get initial cookies
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

            // 6. CRITICAL: Get VALID token with SUCCESSFUL address check
            Console.WriteLine("\n[4/6] Getting valid token...");
            
            // Try with a KNOWN VALID Dutch address first
            string plainXsrfToken = "";
            
            // List of valid Dutch addresses to try
            var validAddresses = new[]
            {
                new { zipcode = "1011AA", house_number = "1" }, // Amsterdam center
                new { zipcode = "3011AB", house_number = "10" }, // Rotterdam
                new { zipcode = "3511AA", house_number = "5" }, // Utrecht
                new { zipcode = "9711AA", house_number = "2" }  // Groningen
            };
            
            foreach (var validAddress in validAddresses)
            {
                Console.WriteLine($"  Trying address: {validAddress.zipcode} {validAddress.house_number}");
                
                var addressCheckData = new { 
                    zipcode = validAddress.zipcode,
                    house_number = validAddress.house_number 
                };
                
                var addressContent = new StringContent(JsonSerializer.Serialize(addressCheckData), Encoding.UTF8, "application/json");
                
                // Build cookie header
                string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={jwtXsrfToken}";
                
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
                    Console.WriteLine($"  ✓ Address check SUCCESS: {addressResponse.StatusCode}");
                    
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
                                    plainXsrfToken = match.Groups[1].Value;
                                    Console.WriteLine($"  Valid token obtained: {plainXsrfToken.Substring(0, Math.Min(10, plainXsrfToken.Length))}...");
                                    
                                    // Update cookie container
                                    cookieContainer.Add(uri, new Cookie("XSRF-TOKEN", plainXsrfToken));
                                    break;
                                }
                            }
                        }
                    }
                    break; // Stop trying addresses once we get a valid one
                }
                else
                {
                    Console.WriteLine($"  ✗ Address failed: {addressResponse.StatusCode}");
                }
            }

            if (string.IsNullOrEmpty(plainXsrfToken))
            {
                Console.WriteLine("❌ Could not get valid token from address checks");
                plainXsrfToken = jwtXsrfToken; // Fallback
            }

            // 7. Prepare form data (use ORIGINAL JSON, not the test address)
            Console.WriteLine("\n[5/6] Preparing form data...");
            var formData = BuildFormData(clientJson);

            // 8. Create client
            Console.WriteLine("\n[6/6] Creating client...");
            
            // Final cookie header with PLAIN token
            string finalCookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={plainXsrfToken}";
            
            var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            clientRequest.Headers.Add("x-csrf-token", plainXsrfToken);
            clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            clientRequest.Headers.Add("Origin", baseUrl);
            clientRequest.Headers.Add("Cookie", finalCookieHeader);
            clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            clientRequest.Headers.Add("Accept-Language", "nl");

            Console.WriteLine($"  Token: {plainXsrfToken}");

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
                
                // Last resort: Try without address check at all
                Console.WriteLine("\n⚠️  Trying alternative: Use token from HTML meta tag...");
                
                // Reload form page to get fresh HTML token
                var formPage = await client.GetAsync($"{baseUrl}/clients/create");
                var formHtml = await formPage.Content.ReadAsStringAsync();
                var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
                var htmlToken = formCsrfMatch.Success ? formCsrfMatch.Groups[1].Value : "";
                
                if (!string.IsNullOrEmpty(htmlToken) && htmlToken != plainXsrfToken)
                {
                    Console.WriteLine($"  HTML token: {htmlToken}");
                    
                    var retryRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
                    {
                        Content = formData
                    };
                    
                    retryRequest.Headers.Add("x-csrf-token", htmlToken);
                    retryRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
                    retryRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
                    retryRequest.Headers.Add("Origin", baseUrl);
                    retryRequest.Headers.Add("Cookie", finalCookieHeader.Replace(plainXsrfToken, htmlToken));
                    
                    var retry = await client.SendAsync(retryRequest);
                    Console.WriteLine($"  Retry status: {retry.StatusCode}");
                    
                    if (retry.IsSuccessStatusCode)
                    {
                        Console.WriteLine("\n✅✅✅ SUCCESS with HTML token! ✅✅✅");
                        return;
                    }
                }
                
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
