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
            // 1. GET login page for initial CSRF
            Console.WriteLine("\n[1/7] Getting login page...");
            var loginPage = await client.GetAsync($"{baseUrl}/login");
            var loginHtml = await loginPage.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var loginCsrf = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  Initial CSRF: {loginCsrf.Substring(0, 10)}...");

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

            // 3. Get Sanctum cookie and add locale
            await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");
            cookieContainer.Add(new Uri(baseUrl), new Cookie("locale", "nl"));

            // 4. Get initial cookies BEFORE loading form
            var uri = new Uri(baseUrl);
            var cookiesBefore = cookieContainer.GetCookies(uri);
            string initialXsrf = "";
            foreach (Cookie c in cookiesBefore)
            {
                if (c.Name == "XSRF-TOKEN") initialXsrf = c.Value;
            }
            Console.WriteLine($"\n[3/7] Initial XSRF: {initialXsrf.Length} chars");

            // 5. CRITICAL: Load form page and capture NEW cookies from Set-Cookie header
            Console.WriteLine("\n[4/7] Loading form page...");
            var formRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/clients/create");
            formRequest.Headers.Add("Cookie", $"locale=nl; XSRF-TOKEN={initialXsrf}; {tenant}_session={GetSessionCookie(cookieContainer, tenant)}");
            
            var formResponse = await client.SendAsync(formRequest);
            var formHtml = await formResponse.Content.ReadAsStringAsync();
            
            // Extract NEW CSRF token from HTML meta tag
            var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var formCsrfToken = formCsrfMatch.Success ? formCsrfMatch.Groups[1].Value : "";
            Console.WriteLine($"  Form CSRF from HTML: {formCsrfToken.Substring(0, Math.Min(10, formCsrfToken.Length))}...");

            // 6. Get cookies AFTER form page load (should have new XSRF)
            var cookiesAfter = cookieContainer.GetCookies(uri);
            string finalXsrf = "";
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            
            foreach (Cookie c in cookiesAfter)
            {
                if (c.Name == "XSRF-TOKEN") 
                {
                    finalXsrf = c.Value;
                    Console.WriteLine($"  New XSRF from cookie: {finalXsrf.Substring(0, Math.Min(10, finalXsrf.Length))}...");
                }
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
            }

            // Use the NEW token from form page load
            string xsrfToUse = !string.IsNullOrEmpty(finalXsrf) ? finalXsrf : formCsrfToken;
            Console.WriteLine($"  Using XSRF: {xsrfToUse.Substring(0, Math.Min(10, xsrfToUse.Length))}...");

            // 7. Prepare form data
            Console.WriteLine("\n[5/7] Preparing form data...");
            var formData = BuildFormData(clientJson);

            // 8. Build EXACT cookie header like browser
            Console.WriteLine("\n[6/7] Building cookie header...");
            string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToUse}";

            // 9. Create client with NEW token
            Console.WriteLine("\n[7/7] Creating client...");
            var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            // Headers matching browser EXACTLY
            clientRequest.Headers.Add("X-CSRF-Token", xsrfToUse);
            clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            clientRequest.Headers.Add("Origin", baseUrl);
            clientRequest.Headers.Add("Cookie", cookieHeader);
            clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            clientRequest.Headers.Add("Accept-Language", "nl");

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
                
                // Try one more time with the HTML token if cookie token failed
                if (response.StatusCode == HttpStatusCode.Unauthorized && formCsrfToken != xsrfToUse)
                {
                    Console.WriteLine("\n⚠️  Trying with HTML CSRF token instead...");
                    clientRequest.Headers.Remove("X-CSRF-Token");
                    clientRequest.Headers.Add("X-CSRF-Token", formCsrfToken);
                    clientRequest.Headers.Remove("Cookie");
                    clientRequest.Headers.Add("Cookie", cookieHeader.Replace(xsrfToUse, formCsrfToken));
                    
                    var retry = await client.SendAsync(clientRequest);
                    Console.WriteLine($"Retry Status: {retry.StatusCode}");
                    if (retry.IsSuccessStatusCode)
                    {
                        Console.WriteLine("\n✅✅✅ SUCCESS with HTML token! ✅✅✅");
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

    static string GetSessionCookie(CookieContainer container, string tenant)
    {
        var cookies = container.GetCookies(new Uri($"https://{tenant}.mijndiad.nl"));
        foreach (Cookie c in cookies)
        {
            if (c.Name == $"{tenant}_session") return c.Value;
        }
        return "";
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
