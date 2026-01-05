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
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36");

        try
        {
            // 1. GET login page
            Console.WriteLine("\n[1/6] Getting login page...");
            var loginPage = await client.GetAsync($"{baseUrl}/login");
            var loginHtml = await loginPage.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var loginCsrf = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  Login CSRF: {loginCsrf}");

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

            // 4. Load form page and capture NEW token from Set-Cookie
            Console.WriteLine("\n[3/6] Loading form page and capturing new token...");
            
            // First, get current XSRF cookie (OLD token)
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            string oldXsrfCookie = "";
            foreach (Cookie c in cookies)
            {
                if (c.Name == "XSRF-TOKEN") oldXsrfCookie = c.Value;
            }
            Console.WriteLine($"  Old XSRF cookie: {oldXsrfCookie.Length} chars");

            // Load form page with OLD token in cookie
            var formRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/clients/create");
            
            // Send request and capture response headers
            var formResponse = await client.SendAsync(formRequest, HttpCompletionOption.ResponseHeadersRead);
            
            // Read Set-Cookie header from response
            string newXsrfTokenFromHeader = "";
            if (formResponse.Headers.TryGetValues("Set-Cookie", out var setCookieValues))
            {
                foreach (var setCookie in setCookieValues)
                {
                    if (setCookie.Contains("XSRF-TOKEN="))
                    {
                        // Extract token from Set-Cookie: XSRF-TOKEN=tokenvalue; path=/; ...
                        var match = Regex.Match(setCookie, @"XSRF-TOKEN=([^;]+)");
                        if (match.Success)
                        {
                            newXsrfTokenFromHeader = match.Groups[1].Value;
                            Console.WriteLine($"  New XSRF from Set-Cookie: {newXsrfTokenFromHeader.Length} chars");
                        }
                    }
                }
            }
            
            // Also get HTML token
            var formHtml = await formResponse.Content.ReadAsStringAsync();
            var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var htmlCsrfToken = formCsrfMatch.Success ? formCsrfMatch.Groups[1].Value : "";
            Console.WriteLine($"  HTML CSRF token: {htmlCsrfToken}");

            // Update cookie container with new token from Set-Cookie
            if (!string.IsNullOrEmpty(newXsrfTokenFromHeader))
            {
                cookieContainer.Add(uri, new Cookie("XSRF-TOKEN", newXsrfTokenFromHeader));
            }

            // 5. Get all cookies for final request
            cookies = cookieContainer.GetCookies(uri);
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            string finalXsrfCookie = "";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
                if (c.Name == "XSRF-TOKEN") finalXsrfCookie = c.Value;
            }

            Console.WriteLine($"\n[4/6] Final cookies:");
            Console.WriteLine($"  Session: {sessionCookie.Length} chars");
            Console.WriteLine($"  Device token: {deviceToken}");
            Console.WriteLine($"  Final XSRF cookie: {finalXsrfCookie.Length} chars");

            // 6. Prepare form data
            Console.WriteLine("\n[5/6] Preparing form data...");
            var formData = BuildFormData(clientJson);

            // 7. Create client with EXACT browser configuration
            Console.WriteLine("\n[6/6] Creating client...");
            
            // Build cookie header EXACTLY like browser
            // Browser keeps OLD XSRF token in cookie but uses NEW token in header!
            string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={oldXsrfCookie}";
            Console.WriteLine($"  Cookie header with OLD XSRF: {oldXsrfCookie.Length} chars");
            
            var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            // CRITICAL: Use lowercase header name like browser
            clientRequest.Headers.Add("x-csrf-token", htmlCsrfToken); // lowercase!
            clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            clientRequest.Headers.Add("Origin", baseUrl);
            clientRequest.Headers.Add("Cookie", cookieHeader);
            clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            clientRequest.Headers.Add("Accept-Language", "nl");

            Console.WriteLine($"  Using HTML token in header: {htmlCsrfToken}");
            Console.WriteLine($"  Using OLD token in cookie: {oldXsrfCookie.Substring(0, Math.Min(20, oldXsrfCookie.Length))}...");

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
                
                // If failed, try with the new token from Set-Cookie
                if (!string.IsNullOrEmpty(newXsrfTokenFromHeader) && newXsrfTokenFromHeader != htmlCsrfToken)
                {
                    Console.WriteLine("\n⚠️  Trying with token from Set-Cookie header...");
                    clientRequest.Headers.Remove("x-csrf-token");
                    clientRequest.Headers.Add("x-csrf-token", newXsrfTokenFromHeader);
                    
                    var retry = await client.SendAsync(clientRequest);
                    Console.WriteLine($"Retry Status: {retry.StatusCode}");
                    if (retry.IsSuccessStatusCode)
                    {
                        Console.WriteLine("\n✅✅✅ SUCCESS with Set-Cookie token! ✅✅✅");
                        return;
                    }
                }
                
                Environment.Exit(1);
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
