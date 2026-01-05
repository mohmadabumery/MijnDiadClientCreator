using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using OtpNet; // Make sure OtpNet package is installed
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        // Validate arguments
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: dotnet run -- --json \"<client-json>\"");
            return;
        }

        string clientJson = args[0];

        string loginUrl = "https://lngvty.mijndiad.nl/login";
        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") ?? throw new Exception("TOTP secret not found in environment variables");
        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") ?? throw new Exception("Username not found");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") ?? throw new Exception("Password not found");

        using HttpClientHandler handler = new HttpClientHandler { CookieContainer = new CookieContainer(), AllowAutoRedirect = true };
        using HttpClient client = new HttpClient(handler);

        try
        {
            Console.WriteLine("== MijnDiAd Auto-Login & Client Creation ==");

            // 1. Fetch login page to get CSRF token
            Console.WriteLine("[1/6] Fetching login page...");
            string loginPageHtml = await client.GetStringAsync(loginUrl);

            Console.WriteLine("[2/6] Extracting CSRF token...");
            string csrfToken = Regex.Match(loginPageHtml, "<meta name=\"csrf-token\" content=\"([^\"]+)\"").Groups[1].Value;
            if (string.IsNullOrEmpty(csrfToken)) throw new Exception("CSRF token not found");
            Console.WriteLine($"  ✓ CSRF token extracted");

            // 2. Generate TOTP
            Totp totp = new Totp(Base32Encoding.ToBytes(totpSecret));
            string totpCode = totp.ComputeTotp();
            Console.WriteLine($"  Generated TOTP: {totpCode}");

            // 3. Log in
            Console.WriteLine("[3/6] Logging in...");
            var loginData = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password),
                new KeyValuePair<string, string>("totp", totpCode)
            });

            client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrfToken);
            HttpResponseMessage loginResponse = await client.PostAsync(loginUrl, loginData);

            if (!loginResponse.IsSuccessStatusCode)
                throw new Exception($"Login failed: {loginResponse.StatusCode}");

            Console.WriteLine("  ✓ Login successful");

            // 4. Refresh Sanctum CSRF (optional)
            Console.WriteLine("[4/6] Refreshing Sanctum CSRF...");
            var csrfRefresh = await client.GetAsync("https://lngvty.mijndiad.nl/sanctum/csrf-cookie");
            csrfRefresh.EnsureSuccessStatusCode();
            Console.WriteLine("  ✓ Sanctum CSRF refreshed");

            // 5. Extract cookies (done automatically via handler)
            Console.WriteLine("[5/6] Extracting cookies...");
            Uri baseUri = new Uri("https://lngvty.mijndiad.nl");
            var cookies = handler.CookieContainer.GetCookies(baseUri);
            Console.WriteLine($"  Total cookies: {cookies.Count}");

            // 6. Create client
            Console.WriteLine("[6/6] Creating client...");
            HttpRequestMessage createRequest = new HttpRequestMessage(HttpMethod.Post, "https://lngvty.mijndiad.nl/api/clients");
            createRequest.Content = new StringContent(clientJson, Encoding.UTF8, "application/json");

            // Add CSRF token from cookie
            string xsrfToken = cookies["XSRF-TOKEN"]?.Value;
            if (!string.IsNullOrEmpty(xsrfToken))
            {
                createRequest.Headers.Add("X-XSRF-TOKEN", xsrfToken);
            }

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
