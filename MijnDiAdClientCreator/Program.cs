using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

        try
        {
            // 1. GET login page
            Console.WriteLine("\n[1/5] Getting login page...");
            var loginPage = await client.GetAsync($"{baseUrl}/login");
            var loginHtml = await loginPage.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var loginCsrf = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  Login CSRF: {loginCsrf}");

            // 2. Login
            Console.WriteLine("\n[2/5] Logging in...");
            var loginData = new { email = username, password = password, totp_code = totp };
            var loginContent = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");
            
            var loginRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/login")
            {
                Content = loginContent
            };
            loginRequest.Headers.Add("X-CSRF-TOKEN", loginCsrf);
            loginRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            loginRequest.Headers.Add("Referer", $"{baseUrl}/login");
            loginRequest.Headers.Add("Origin", baseUrl);
            
            var loginResponse = await client.SendAsync(loginRequest);
            var loginBody = await loginResponse.Content.ReadAsStringAsync();
            
            if (!loginResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Login failed: {loginResponse.StatusCode}");
                Console.WriteLine(loginBody);
                return;
            }
            Console.WriteLine("  ✓ Login successful");

            // 3. Load form page IMMEDIATELY
            Console.WriteLine("\n[3/5] Loading form page...");
            var formResponse = await client.GetAsync($"{baseUrl}/clients/create");
            var formHtml = await formResponse.Content.ReadAsStringAsync();
            
            // Extract CSRF from form HTML
            var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var csrfToken = formCsrfMatch.Success ? formCsrfMatch.Groups[1].Value : "";
            Console.WriteLine($"  Form CSRF: {csrfToken}");

            // 4. Get cookies IMMEDIATELY
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            string xsrfCookie = "";
            string locale = "nl";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
                if (c.Name == "XSRF-TOKEN") xsrfCookie = c.Value;
                if (c.Name == "locale") locale = c.Value;
            }

            Console.WriteLine($"\n[4/5] Session state:");
            Console.WriteLine($"  Session: {sessionCookie.Substring(0, 10)}...");
            Console.WriteLine($"  Device: {deviceToken}");
            Console.WriteLine($"  CSRF token: {csrfToken}");

            // 5. POST client data IMMEDIATELY (no delay!)
            Console.WriteLine("\n[5/5] Creating client...");
            
            // Build cookie header exactly like browser
            var cookieHeader = $"locale={locale}; md-device-token={deviceToken}; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfCookie}";
            
            // Use multipart form data like a real browser form submission
            var formData = BuildFormData(clientJson);
            
            var apiRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            // Use the CSRF token from the form page
            apiRequest.Headers.Add("x-csrf-token", csrfToken);
            apiRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            apiRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            apiRequest.Headers.Add("Origin", baseUrl);
            apiRequest.Headers.Add("Cookie", cookieHeader);
            apiRequest.Headers.Add("Accept", "application/json, text/plain, */*");

            var apiResponse = await client.SendAsync(apiRequest);
            var responseBody = await apiResponse.Content.ReadAsStringAsync();
            
            Console.WriteLine($"\n== Response: {apiResponse.StatusCode} ==");
            
            if (apiResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("\n✅✅✅ SUCCESS! Client created ✅✅✅");
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
            else
            {
                Console.WriteLine($"❌ Failed");
                Console.WriteLine(responseBody);
                
                // Try one more time with URL-decoded XSRF in header
                Console.WriteLine("\n  Retry with decoded XSRF...");
                var decodedXsrf = Uri.UnescapeDataString(xsrfCookie);
                var decodedCsrf = decodedXsrf.Length >= 40 ? decodedXsrf.Substring(0, 40) : decodedXsrf;
                
                apiRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
                {
                    Content = BuildFormData(clientJson)
                };
                apiRequest.Headers.Add("x-csrf-token", decodedCsrf);
                apiRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
                apiRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
                apiRequest.Headers.Add("Origin", baseUrl);
                apiRequest.Headers.Add("Cookie", cookieHeader);
                apiRequest.Headers.Add("Accept", "application/json, text/plain, */*");
                
                apiResponse = await client.SendAsync(apiRequest);
                responseBody = await apiResponse.Content.ReadAsStringAsync();
                
                Console.WriteLine($"  Retry Status: {apiResponse.StatusCode}");
                
                if (apiResponse.IsSuccessStatusCode)
                {
                    Console.WriteLine("\n✅✅✅ SUCCESS on retry! ✅✅✅");
                    Console.WriteLine(responseBody);
                }
                else
                {
                    Console.WriteLine($"  Still failed: {responseBody}");
                    Environment.Exit(1);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
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
