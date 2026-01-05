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

            // 4. Load form page to get fresh CSRF
            Console.WriteLine("\n[3/7] Loading form page...");
            var formRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/clients/create");
            
            var formResponse = await client.SendAsync(formRequest);
            var formHtml = await formResponse.Content.ReadAsStringAsync();
            
            // Extract CSRF from HTML (this is the plain 40-char token)
            var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var htmlCsrfToken = formCsrfMatch.Success ? formCsrfMatch.Groups[1].Value : "";
            Console.WriteLine($"  HTML CSRF token: {htmlCsrfToken.Length} chars");

            // 5. Get all cookies
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

            Console.WriteLine($"\n[4/7] Cookies extracted:");
            Console.WriteLine($"  Session: {sessionCookie.Length} chars");
            Console.WriteLine($"  Device token: {deviceToken}");
            Console.WriteLine($"  XSRF cookie: {xsrfCookie.Length} chars");

            // 6. Prepare form data
            Console.WriteLine("\n[5/7] Preparing form data...");
            var formData = BuildFormData(clientJson);

            // 7. Try different CSRF token combinations
            Console.WriteLine("\n[6/7] Creating client (trying different tokens)...");
            
            // List of tokens to try in order
            var tokenCandidates = new List<(string name, string token)>
            {
                ("HTML Token", htmlCsrfToken),
                ("Cookie XSRF (raw)", xsrfCookie),
                ("Cookie XSRF (URL-decoded)", Uri.UnescapeDataString(xsrfCookie)),
                ("HTML first 40 chars", htmlCsrfToken.Length >= 40 ? htmlCsrfToken.Substring(0, 40) : ""),
                ("Cookie first 40 chars", xsrfCookie.Length >= 40 ? xsrfCookie.Substring(0, 40) : "")
            };

            // Remove empty tokens
            tokenCandidates = tokenCandidates.Where(t => !string.IsNullOrEmpty(t.token)).ToList();

            bool success = false;
            
            for (int i = 0; i < tokenCandidates.Count; i++)
            {
                var (tokenName, tokenValue) = tokenCandidates[i];
                Console.WriteLine($"\n  Attempt {i+1}: {tokenName} ({tokenValue.Length} chars)...");
                
                // Build cookie header EXACTLY like browser
                string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfCookie}";
                
                var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
                {
                    Content = formData
                };

                clientRequest.Headers.Add("X-CSRF-Token", tokenValue);
                clientRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
                clientRequest.Headers.Add("Referer", $"{baseUrl}/clients/create");
                clientRequest.Headers.Add("Origin", baseUrl);
                clientRequest.Headers.Add("Cookie", cookieHeader);
                clientRequest.Headers.Add("Accept", "application/json, text/plain, */*");
                clientRequest.Headers.Add("Accept-Language", "nl");

                var response = await client.SendAsync(clientRequest);
                var responseBody = await response.Content.ReadAsStringAsync();
                
                Console.WriteLine($"    Status: {response.StatusCode}");
                
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"\n✅✅✅ SUCCESS with {tokenName}! ✅✅✅");
                    if (!string.IsNullOrEmpty(responseBody))
                    {
                        try
                        {
                            var json = JsonSerializer.Deserialize<JsonElement>(responseBody);
                            Console.WriteLine(JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true }));
                        }
                        catch
                        {
                            Console.WriteLine($"Response: {responseBody}");
                        }
                    }
                    success = true;
                    break;
                }
                else if (response.StatusCode == HttpStatusCode.UnprocessableEntity)
                {
                    try
                    {
                        var json = JsonSerializer.Deserialize<JsonElement>(responseBody);
                        if (json.TryGetProperty("messages", out var messages) && messages.GetArrayLength() > 0)
                        {
                            Console.WriteLine($"    Error: {messages[0]}");
                        }
                    }
                    catch { }
                }
            }

            if (!success)
            {
                Console.WriteLine("\n[7/7] ❌ All attempts failed");
                Console.WriteLine("\n=== DEBUG INFO ===");
                Console.WriteLine($"HTML Token: {htmlCsrfToken}");
                Console.WriteLine($"XSRF Cookie (first 100 chars): {xsrfCookie.Substring(0, Math.Min(100, xsrfCookie.Length))}...");
                Console.WriteLine($"Session exists: {!string.IsNullOrEmpty(sessionCookie)}");
                Console.WriteLine($"Device token: {deviceToken}");
                Console.WriteLine($"mdsb cookie: {!string.IsNullOrEmpty(mdsbCookie)}");
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
