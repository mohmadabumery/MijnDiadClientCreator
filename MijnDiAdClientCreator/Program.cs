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
            Console.WriteLine("\n[1/7] Getting login page...");
            var loginPage = await client.GetAsync($"{baseUrl}/login");
            var loginHtml = await loginPage.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var loginCsrf = csrfMatch.Groups[1].Value;

            // 2. Login
            Console.WriteLine("\n[2/7] Logging in...");
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
            Console.WriteLine("\n[3/7] Loading form page...");
            await client.GetAsync($"{baseUrl}/clients/create");

            // 5. Get initial cookies
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            string oldXsrfToken = "";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
                if (c.Name == "XSRF-TOKEN") oldXsrfToken = c.Value;
            }

            Console.WriteLine($"  Session: {sessionCookie.Length} chars");
            Console.WriteLine($"  Old XSRF: {oldXsrfToken.Length} chars");

            // 6. CRITICAL: Call /api/address/check to get FRESH token
            Console.WriteLine("\n[4/7] Calling /api/address/check for fresh token...");
            
            // Extract address from JSON
            var clientData = JsonSerializer.Deserialize<JsonElement>(clientJson);
            string zipcode = "";
            string houseNumber = "";
            
            if (clientData.TryGetProperty("address", out var address))
            {
                if (address.TryGetProperty("zipcode", out var zip)) zipcode = zip.GetString() ?? "";
                if (address.TryGetProperty("house_number", out var house)) houseNumber = house.GetString() ?? "";
            }

            var addressCheckData = new { zipcode = zipcode, house_number = houseNumber };
            var addressContent = new StringContent(JsonSerializer.Serialize(addressCheckData), Encoding.UTF8, "application/json");
            
            var addressRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/address/check")
            {
                Content = addressContent
            };
            
            // Build cookie header with OLD token
            string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={oldXsrfToken}";
            
            addressRequest.Headers.Add("x-csrf-token", oldXsrfToken);
            addressRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            addressRequest.Headers.Add("Origin", baseUrl);
            addressRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            addressRequest.Headers.Add("Cookie", cookieHeader);
            addressRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            addressRequest.Headers.Add("Accept-Language", "nl");

            var addressResponse = await client.SendAsync(addressRequest);
            var addressBody = await addressResponse.Content.ReadAsStringAsync();
            
            Console.WriteLine($"  Address check status: {addressResponse.StatusCode}");
            
            // Extract NEW token from Set-Cookie header
            string freshXsrfToken = "";
            if (addressResponse.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                {
                    if (setCookie.Contains("XSRF-TOKEN="))
                    {
                        var match = Regex.Match(setCookie, @"XSRF-TOKEN=([^;]+)");
                        if (match.Success)
                        {
                            freshXsrfToken = match.Groups[1].Value;
                            Console.WriteLine($"  Fresh XSRF token: {freshXsrfToken}");
                            
                            // Update cookie container with new token
                            cookieContainer.Add(uri, new Cookie("XSRF-TOKEN", freshXsrfToken));
                        }
                    }
                }
            }

            if (string.IsNullOrEmpty(freshXsrfToken))
            {
                Console.WriteLine("❌ No fresh token from address check");
                freshXsrfToken = oldXsrfToken; // Fallback
            }

            // 7. Prepare form data for client creation
            Console.WriteLine("\n[5/7] Preparing form data...");
            var formData = BuildFormData(clientJson);

            // 8. Create client with FRESH token
            Console.WriteLine("\n[6/7] Creating client...");
            
            // Update cookie header with FRESH token
            cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={freshXsrfToken}";
            
            var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            clientRequest.Headers.Add("x-csrf-token", freshXsrfToken);
            clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            clientRequest.Headers.Add("Origin", baseUrl);
            clientRequest.Headers.Add("Cookie", cookieHeader);
            clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            clientRequest.Headers.Add("Accept-Language", "nl");

            Console.WriteLine($"  Using fresh token: {freshXsrfToken}");

            var response = await client.SendAsync(clientRequest);
            var responseBody = await response.Content.ReadAsStringAsync();
            
            Console.WriteLine($"\n[7/7] Response:");
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
                
                // If failed with fresh token, try old token as fallback
                if (freshXsrfToken != oldXsrfToken)
                {
                    Console.WriteLine("\n⚠️  Trying with old token as fallback...");
                    clientRequest.Headers.Remove("x-csrf-token");
                    clientRequest.Headers.Add("x-csrf-token", oldXsrfToken);
                    clientRequest.Headers.Remove("Cookie");
                    clientRequest.Headers.Add("Cookie", cookieHeader.Replace(freshXsrfToken, oldXsrfToken));
                    
                    var retry = await client.SendAsync(clientRequest);
                    Console.WriteLine($"Retry Status: {retry.StatusCode}");
                    if (retry.IsSuccessStatusCode)
                    {
                        Console.WriteLine("\n✅✅✅ SUCCESS with old token! ✅✅✅");
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
