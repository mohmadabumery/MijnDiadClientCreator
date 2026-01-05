using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using OtpNet;

class Program
{
    static async Task Main(string[] args)
    {
        string clientJson;
        
        if (args.Length >= 2 && args[0] == "--json-file")
        {
            string filePath = args[1];
            Console.WriteLine($"Reading JSON from file: {filePath}");
            clientJson = await File.ReadAllTextAsync(filePath);
        }
        else if (File.Exists("client_data.json"))
        {
            Console.WriteLine("Reading JSON from default file: client_data.json");
            clientJson = await File.ReadAllTextAsync("client_data.json");
        }
        else
        {
            Console.WriteLine("Usage: dotnet run -- --json-file data.json");
            return;
        }

        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? throw new Exception("MIJNDIAD_TENANT not set");
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") ?? throw new Exception("MIJNDIAD_USERNAME not set");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") ?? throw new Exception("MIJNDIAD_PASSWORD not set");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") ?? throw new Exception("MIJNDIAD_TOTP_SECRET not set");
        var totp = GenerateTotp(totpSecret);

        var baseUrl = $"https://{tenant}.mijndiad.nl";

        Console.WriteLine("\n== MijnDiAd Auto-Login & Client Creation ==");
        Console.WriteLine($"Base URL: {baseUrl}");

        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All,
            AllowAutoRedirect = false
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(30);
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36");
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("Accept-Language", "nl");

        try
        {
            // 1. Get login page
            Console.WriteLine("\n[1/9] Getting login page...");
            var loginPage = await client.GetAsync($"{baseUrl}/login");
            var loginHtml = await loginPage.Content.ReadAsStringAsync();
            
            // 2. Extract initial CSRF token
            var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!csrfMatch.Success)
            {
                Console.WriteLine("❌ CSRF token not found");
                return;
            }
            var initialCsrfToken = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  Initial CSRF: {initialCsrfToken.Substring(0, Math.Min(10, initialCsrfToken.Length))}...");

            // 3. Login
            Console.WriteLine("\n[2/9] Logging in...");
            Console.WriteLine($"  TOTP: {totp}");
            
            var loginData = new { email = username, password = password, totp_code = totp };
            var loginContent = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");
            
            var loginRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/login")
            {
                Content = loginContent
            };
            loginRequest.Headers.Add("X-CSRF-TOKEN", initialCsrfToken);
            loginRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            loginRequest.Headers.Add("Origin", baseUrl);
            loginRequest.Headers.Add("Referer", $"{baseUrl}/login");
            
            var loginResponse = await client.SendAsync(loginRequest);
            if (!loginResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Login failed: {loginResponse.StatusCode}");
                return;
            }
            Console.WriteLine("  ✓ Login successful");

            // 4. Refresh Sanctum cookie
            Console.WriteLine("\n[3/9] Refreshing Sanctum cookie...");
            await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");

            // 5. Add locale cookie
            cookieContainer.Add(new Uri(baseUrl), new Cookie("locale", "nl"));
            
            // 6. Get ALL cookies
            Console.WriteLine("\n[4/9] Getting cookies...");
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            
            // Get the plain XSRF token from cookie (not URL-decoded)
            string plainXsrfToken = "";
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == "XSRF-TOKEN") plainXsrfToken = c.Value;
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
            }
            
            Console.WriteLine($"  XSRF: {plainXsrfToken.Length} chars");
            Console.WriteLine($"  Session: {sessionCookie.Length} chars");

            // 7. Verify session
            Console.WriteLine("\n[5/9] Verifying session...");
            var userRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/user");
            userRequest.Headers.Add("X-CSRF-Token", plainXsrfToken);
            userRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            userRequest.Headers.Add("Referer", $"{baseUrl}/");
            
            var userResponse = await client.SendAsync(userRequest);
            if (!userResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Session failed: {userResponse.StatusCode}");
                return;
            }
            Console.WriteLine("  ✓ Session verified");

            // 8. Load form page and get FRESH CSRF token
            Console.WriteLine("\n[6/9] Loading form page...");
            var formRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/clients/create");
            formRequest.Headers.Add("X-CSRF-Token", plainXsrfToken);
            formRequest.Headers.Add("Referer", $"{baseUrl}/clients");
            
            var formResponse = await client.SendAsync(formRequest);
            var formHtml = await formResponse.Content.ReadAsStringAsync();
            
            // Extract FRESH CSRF token from form page
            var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            string formCsrfToken = formCsrfMatch.Success ? formCsrfMatch.Groups[1].Value : plainXsrfToken;
            Console.WriteLine($"  Form CSRF: {formCsrfToken.Substring(0, Math.Min(10, formCsrfToken.Length))}...");

            // 9. Prepare form data
            Console.WriteLine("\n[7/9] Preparing form data...");
            var formData = new MultipartFormDataContent();
            AddFormDataFromJson(formData, clientJson);
            
            // 10. Build COMPLETE cookie string (like browser)
            Console.WriteLine("\n[8/9] Building cookie header...");
            string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={plainXsrfToken}";
            Console.WriteLine($"  Cookie length: {cookieHeader.Length}");

            // 11. Create client with EXACT browser headers
            Console.WriteLine("\n[9/9] Creating client...");
            var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
            {
                Content = formData
            };

            // CRITICAL: Match browser EXACTLY
            clientRequest.Headers.Add("X-CSRF-Token", formCsrfToken); // Use form token
            clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
            clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
            clientRequest.Headers.Add("Origin", baseUrl);
            clientRequest.Headers.Add("Cookie", cookieHeader);
            clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
            clientRequest.Headers.Add("Accept-Language", "nl");
            clientRequest.Headers.Add("Accept-Encoding", "gzip, deflate, br, zstd");
            clientRequest.Headers.Add("Sec-Ch-Ua", "\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"");
            clientRequest.Headers.Add("Sec-Ch-Ua-Mobile", "?0");
            clientRequest.Headers.Add("Sec-Ch-Ua-Platform", "\"Windows\"");
            clientRequest.Headers.Add("Sec-Fetch-Dest", "empty");
            clientRequest.Headers.Add("Sec-Fetch-Mode", "cors");
            clientRequest.Headers.Add("Sec-Fetch-Site", "same-origin");
            clientRequest.Headers.Add("Priority", "u=1, i");

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
                Console.WriteLine("\n❌ Failed to create client");
                Environment.Exit(1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ Error: {ex.Message}");
            Environment.Exit(1);
        }
    }

    static void AddFormDataFromJson(MultipartFormDataContent formData, string json)
    {
        var data = JsonSerializer.Deserialize<JsonElement>(json);
        ProcessElement(formData, data, "");
    }

    static void ProcessElement(MultipartFormDataContent formData, JsonElement element, string prefix)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    string key = string.IsNullOrEmpty(prefix) ? prop.Name : $"{prefix}[{prop.Name}]";
                    ProcessElement(formData, prop.Value, key);
                }
                break;
                
            case JsonValueKind.Array:
                int i = 0;
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object || item.ValueKind == JsonValueKind.Array)
                    {
                        ProcessElement(formData, item, $"{prefix}[{i}]");
                    }
                    else
                    {
                        formData.Add(new StringContent(GetValue(item)), $"{prefix}[]");
                    }
                    i++;
                }
                if (i == 0) formData.Add(new StringContent(""), $"{prefix}[]");
                break;
                
            default:
                formData.Add(new StringContent(GetValue(element)), prefix);
                break;
        }
    }

    static string GetValue(JsonElement element)
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
