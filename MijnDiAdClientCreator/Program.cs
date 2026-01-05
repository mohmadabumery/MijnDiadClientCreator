using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;
using System.Web;
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
            Console.WriteLine("\n[1/8] Getting login page...");
            var loginPage = await client.GetAsync($"{baseUrl}/login");
            var loginHtml = await loginPage.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var loginCsrf = csrfMatch.Groups[1].Value;
            Console.WriteLine($"  Initial CSRF: {loginCsrf.Substring(0, Math.Min(10, loginCsrf.Length))}...");

            // 2. Login
            Console.WriteLine("\n[2/8] Logging in...");
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

            // 4. Get initial XSRF token
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            string initialXsrf = "";
            foreach (Cookie c in cookies)
            {
                if (c.Name == "XSRF-TOKEN") initialXsrf = c.Value;
            }
            Console.WriteLine($"\n[3/8] Initial XSRF cookie: {initialXsrf.Length} chars");

            // 5. Load form page with current cookies
            Console.WriteLine("\n[4/8] Loading form page...");
            var formRequest = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/clients/create");
            
            var formResponse = await client.SendAsync(formRequest);
            var formHtml = await formResponse.Content.ReadAsStringAsync();
            
            // Extract CSRF from HTML
            var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var htmlCsrfToken = formCsrfMatch.Success ? formCsrfMatch.Groups[1].Value : "";
            Console.WriteLine($"  HTML CSRF: {htmlCsrfToken.Substring(0, Math.Min(10, htmlCsrfToken.Length))}...");

            // 6. Get updated cookies after form page load
            cookies = cookieContainer.GetCookies(uri);
            string finalXsrf = "";
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == "XSRF-TOKEN") 
                {
                    finalXsrf = c.Value;
                    Console.WriteLine($"  Cookie XSRF: {finalXsrf.Length} chars");
                }
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
            }

            // 7. DECODE the XSRF token from cookie
            Console.WriteLine("\n[5/8] Decoding tokens...");
            string decodedXsrf = DecodeXsrfToken(finalXsrf);
            string decodedHtmlToken = DecodeXsrfToken(htmlCsrfToken);
            
            Console.WriteLine($"  Decoded cookie XSRF: {decodedXsrf?.Length ?? 0} chars");
            Console.WriteLine($"  Decoded HTML token: {decodedHtmlToken?.Length ?? 0} chars");
            
            // Try which token works
            string[] tokenAttempts = new[] { decodedHtmlToken, decodedXsrf, htmlCsrfToken, finalXsrf };
            string[] attemptNames = new[] { "Decoded HTML", "Decoded Cookie", "Raw HTML", "Raw Cookie" };

            // 8. Prepare form data
            Console.WriteLine("\n[6/8] Preparing form data...");
            var formData = BuildFormData(clientJson);

            // 9. Try each token
            Console.WriteLine("\n[7/8] Creating client...");
            bool success = false;
            
            for (int i = 0; i < tokenAttempts.Length; i++)
            {
                if (string.IsNullOrEmpty(tokenAttempts[i])) continue;
                
                Console.WriteLine($"\n  Attempt {i+1}: {attemptNames[i]} token ({tokenAttempts[i].Length} chars)...");
                
                string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={finalXsrf}";
                
                var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
                {
                    Content = formData
                };

                clientRequest.Headers.Add("X-CSRF-Token", tokenAttempts[i]);
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
                    Console.WriteLine($"\n✅✅✅ SUCCESS with {attemptNames[i]} token! ✅✅✅");
                    Console.WriteLine($"Response: {responseBody}");
                    success = true;
                    break;
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

            if (!success)
            {
                Console.WriteLine("\n[8/8] ❌ All token attempts failed");
                Console.WriteLine("\n=== DEBUG INFO ===");
                Console.WriteLine($"HTML Token (raw): {htmlCsrfToken}");
                Console.WriteLine($"Cookie XSRF (raw): {finalXsrf?.Substring(0, Math.Min(50, finalXsrf?.Length ?? 0))}...");
                Console.WriteLine($"Session cookie: {sessionCookie?.Length ?? 0} chars");
                Environment.Exit(1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ Error: {ex.Message}");
            Environment.Exit(1);
        }
    }

    // Decode the XSRF token - might be URL-encoded or JWT-encoded
    static string DecodeXsrfToken(string encodedToken)
    {
        if (string.IsNullOrEmpty(encodedToken)) return "";
        
        try
        {
            // Try URL decode first
            string decoded = HttpUtility.UrlDecode(encodedToken);
            
            // If it looks like a JWT (starts with eyJ), try to decode it
            if (decoded.StartsWith("eyJ"))
            {
                try
                {
                    // JWT format: header.payload.signature
                    var parts = decoded.Split('.');
                    if (parts.Length >= 2)
                    {
                        // Decode payload (middle part)
                        string payload = parts[1];
                        // Add padding if needed
                        while (payload.Length % 4 != 0) payload += "=";
                        var payloadBytes = Convert.FromBase64String(payload);
                        var payloadJson = Encoding.UTF8.GetString(payloadBytes);
                        
                        // Try to parse and extract "value" field
                        var json = JsonSerializer.Deserialize<JsonElement>(payloadJson);
                        if (json.TryGetProperty("value", out var value))
                        {
                            return value.GetString() ?? "";
                        }
                    }
                }
                catch
                {
                    // If JWT decode fails, return URL-decoded version
                }
            }
            
            return decoded;
        }
        catch
        {
            return encodedToken; // Return original if decoding fails
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
