using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using OtpNet; // TOTP

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: dotnet run -- --json \"<client-json>\"");
            return;
        }

        string clientJson = args[0];

        string baseUrl = "https://lngvty.mijndiad.nl";
        string loginUrl = $"{baseUrl}/login";
        string csrfUrl = $"{baseUrl}/sanctum/csrf-cookie";

        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") 
            ?? throw new Exception("TOTP secret not found in environment variables");
        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") 
            ?? throw new Exception("Username not found");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") 
            ?? throw new Exception("Password not found");

        using HttpClientHandler handler = new HttpClientHandler
        {
            CookieContainer = new CookieContainer(),
            AllowAutoRedirect = true
        };
        using HttpClient client = new HttpClient(handler);

        try
        {
            Console.WriteLine("== MijnDiAd Auto-Login & Client Creation ==");

            // 1. Refresh Sanctum CSRF cookie
            Console.WriteLine("[1/6] Getting CSRF cookie...");
            var csrfRefresh = await client.GetAsync(csrfUrl);
            csrfRefresh.EnsureSuccessStatusCode();
            Console.WriteLine("  ✓ CSRF cookie received");

            // 2. Generate TOTP
            Totp totp = new Totp(Base32Encoding.ToBytes(totpSecret));
            string totpCode = totp.ComputeTotp();
            Console.WriteLine($"  Generated TOTP: {totpCode}");

            // 3. Log in using JSON
            Console.WriteLine("[2/6] Logging in...");
            var loginBody = new
            {
                username = username,
                password = password,
                totp = totpCode
            };
            string loginJson = JsonSerializer.Serialize(loginBody);
            var loginRequest = new HttpRequestMessage(HttpMethod.Post, loginUrl)
            {
                Content = new StringContent(loginJson, Encoding.UTF8, "application/json")
            };

            // Add CSRF token from cookie
            var xsrfToken = handler.CookieContainer.GetCookies(new Uri(baseUrl))["XSRF-TOKEN"]?.Value;
            if (!string.IsNullOrEmpty(xsrfToken))
                loginRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);

            var loginResponse = await client.SendAsync(loginRequest);
            if (!loginResponse.IsSuccessStatusCode)
                throw new Exception($"Login failed: {loginResponse.StatusCode}");

            Console.WriteLine("  ✓ Login successful");

            // 4. Bind session to API (optional)
            Console.WriteLine("[3/6] Binding API session...");
            var bindResponse = await client.GetAsync($"{baseUrl}/api/user");
            bindResponse.EnsureSuccessStatusCode();
            Console.WriteLine("  ✓ API session bound");

            // 5. Prepare cookies (handler manages cookies automatically)
            Console.WriteLine("[4/6] Cookies ready...");
            var cookies = handler.CookieContainer.GetCookies(new Uri(baseUrl));
            Console.WriteLine($"  Total cookies: {cookies.Count}");

            // 6. Create client
            Console.WriteLine("[5/6] Creating client...");
            HttpRequestMessage createRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/clients");
            createRequest.Content = new StringContent(clientJson, Encoding.UTF8, "application/json");

            // Add CSRF token
            xsrfToken = cookies["XSRF-TOKEN"]?.Value;
            if (!string.IsNullOrEmpty(xsrfToken))
                createRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);

            HttpResponseMessage createResponse = await client.SendAsync(createRequest);
            string responseContent = await createResponse.Content.ReadAsStringAsync();

            if (createResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("✅ Client successfully created in MijnDiAd EPD");
            }
            else
            {
                Console.WriteLine($"❌ Client creation failed: {createResponse.StatusCode}");
                Console.WriteLine(responseContent);
                throw new Exception("Client creation failed");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Environment.Exit(-1);
        }
    }
}
