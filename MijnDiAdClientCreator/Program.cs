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
            Console.WriteLine("\n[1/5] Getting login page...");
            var loginPage = await client.GetAsync($"{baseUrl}/login");
            var loginHtml = await loginPage.Content.ReadAsStringAsync();
            var csrfMatch = Regex.Match(loginHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var loginCsrf = csrfMatch.Groups[1].Value;

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
            Console.WriteLine("\n[3/5] Loading form page...");
            var formResponse = await client.GetAsync($"{baseUrl}/clients/create");
            var formHtml = await formResponse.Content.ReadAsStringAsync();
            
            // Get HTML token
            var formCsrfMatch = Regex.Match(formHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            var htmlToken = formCsrfMatch.Success ? formCsrfMatch.Groups[1].Value : "";
            Console.WriteLine($"  HTML token: {htmlToken}");

            // 5. Get JWT cookie and decode it
            Console.WriteLine("\n[4/5] Decoding JWT token...");
            var uri = new Uri(baseUrl);
            var cookies = cookieContainer.GetCookies(uri);
            
            string jwtToken = "";
            string sessionCookie = "";
            string deviceToken = "";
            string mdsbCookie = "";
            
            foreach (Cookie c in cookies)
            {
                if (c.Name == "XSRF-TOKEN") jwtToken = c.Value;
                if (c.Name == $"{tenant}_session") sessionCookie = c.Value;
                if (c.Name == "md-device-token") deviceToken = c.Value;
                if (c.Name == "mdsb") mdsbCookie = c.Value;
            }

            // DECODE the JWT to get actual token
            string decodedToken = DecodeJwtToken(jwtToken);
            Console.WriteLine($"  JWT token: {jwtToken.Substring(0, Math.Min(30, jwtToken.Length))}...");
            Console.WriteLine($"  Decoded token: {decodedToken?.Substring(0, Math.Min(30, decodedToken?.Length ?? 0))}...");

            // 6. Prepare form data
            Console.WriteLine("\n[5/5] Creating client...");
            var formData = BuildFormData(clientJson);
            
            // Try BOTH tokens (decoded JWT and HTML)
            var tokensToTry = new[] { decodedToken, htmlToken };
            var tokenNames = new[] { "Decoded JWT", "HTML" };
            
            for (int i = 0; i < tokensToTry.Length; i++)
            {
                if (string.IsNullOrEmpty(tokensToTry[i])) continue;
                
                Console.WriteLine($"\n  Attempt {i+1}: {tokenNames[i]} token...");
                
                string cookieHeader = $"locale=nl; md-device-token={deviceToken}; addToHomescreenCalled=true; mdsb={mdsbCookie}; {tenant}_session={sessionCookie}; XSRF-TOKEN={jwtToken}";
                
                var clientRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients")
                {
                    Content = formData
                };

                clientRequest.Headers.Add("x-csrf-token", tokensToTry[i]); // lowercase!
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
                    Console.WriteLine($"\n✅✅✅ SUCCESS with {tokenNames[i]} token! ✅✅✅");
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
                    return;
                }
                else
                {
                    Console.WriteLine($"    Response: {responseBody}");
                }
            }
            
            Console.WriteLine("\n❌ All attempts failed");
            Console.WriteLine("\n=== DEBUG ===");
            Console.WriteLine($"JWT: {jwtToken}");
            Console.WriteLine($"Decoded: {decodedToken}");
            Console.WriteLine($"HTML: {htmlToken}");
            Console.WriteLine($"Session: {sessionCookie.Length} chars");
            Environment.Exit(1);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ Error: {ex.Message}");
            Environment.Exit(1);
        }
    }

    // Decode JWT token to extract the actual CSRF token
    static string DecodeJwtToken(string jwt)
    {
        if (string.IsNullOrEmpty(jwt) || !jwt.Contains('.'))
            return jwt;
        
        try
        {
            // JWT format: header.payload.signature
            var parts = jwt.Split('.');
            if (parts.Length < 2) return jwt;
            
            // Decode payload (middle part)
            string payload = parts[1];
            
            // Fix base64 padding
            payload = payload.Replace('-', '+').Replace('_', '/');
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }
            
            var payloadBytes = Convert.FromBase64String(payload);
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);
            
            // Parse JSON and extract "value" field
            using var doc = JsonDocument.Parse(payloadJson);
            if (doc.RootElement.TryGetProperty("value", out var valueElement))
            {
                return valueElement.GetString() ?? "";
            }
            
            // If no "value" field, try "iv" or other fields
            if (doc.RootElement.TryGetProperty("iv", out var ivElement))
            {
                return ivElement.GetString() ?? "";
            }
            
            return jwt; // Return original if we can't decode
        }
        catch
        {
            return jwt; // Return original if decoding fails
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
