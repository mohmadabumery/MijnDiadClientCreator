using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using OtpNet;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("❌ Please provide client JSON as argument.");
            return;
        }

        string clientJson = args[0];
        string baseUrl = "https://lngvty.mijndiad.nl"; // base URL

        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(totpSecret))
        {
            Console.WriteLine("❌ Missing MIJNDIAD credentials or TOTP secret in environment variables.");
            return;
        }

        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            UseCookies = true,
            AllowAutoRedirect = true
        };

        using var client = new HttpClient(handler) { BaseAddress = new Uri(baseUrl) };

        Console.WriteLine("== MijnDiAd Auto-Login & Client Creation ==");

        try
        {
            // 1. Fetch login page to get initial CSRF token
            Console.WriteLine("[1/6] Fetching login page...");
            var loginPageResp = await client.GetAsync("/login");
            loginPageResp.EnsureSuccessStatusCode();

            string xsrf = null;
            foreach (Cookie c in cookieContainer.GetCookies(new Uri(baseUrl)))
            {
                if (c.Name == "XSRF-TOKEN") xsrf = c.Value;
            }

            if (xsrf == null)
            {
                Console.WriteLine("❌ XSRF cookie missing on login page.");
                return;
            }
            Console.WriteLine("[2/6] Extracted initial CSRF token.");

            // 2. Generate TOTP
            var totp = new Totp(Base32Encoding.ToBytes(totpSecret));
            string totpCode = totp.ComputeTotp();
            Console.WriteLine("[3/6] Generated TOTP: " + totpCode);

            // 3. Perform login POST
            var loginData = new
            {
                username,
                password,
                totp = totpCode
            };
            var loginContent = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrf);
            client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");

            Console.WriteLine("[4/6] Logging in...");
            var loginResp = await client.PostAsync("/login", loginContent);

            if (loginResp.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine("❌ Login failed: " + loginResp.StatusCode);
                return;
            }
            Console.WriteLine("  ✓ Login successful");

            // 4. Bind session to API (/api/user)
            Console.WriteLine("[5/6] Binding session to API...");
            var bindResp = await client.GetAsync("/api/user");
            bindResp.EnsureSuccessStatusCode();
            Console.WriteLine("  ✓ API session bound");

            // 5. Refresh CSRF before client creation
            Console.WriteLine("[6/6] Refreshing Sanctum CSRF for client creation...");
            var csrfResp = await client.GetAsync("/sanctum/csrf-cookie");
            csrfResp.EnsureSuccessStatusCode();

            xsrf = null;
            foreach (Cookie c in cookieContainer.GetCookies(new Uri(baseUrl)))
            {
                if (c.Name == "XSRF-TOKEN") xsrf = c.Value;
            }

            if (xsrf == null)
            {
                Console.WriteLine("❌ XSRF cookie missing after refresh");
                return;
            }

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrf);
            client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
            client.DefaultRequestHeaders.Add("Origin", baseUrl);
            client.DefaultRequestHeaders.Add("Referer", baseUrl);

            // 6. Create client
            Console.WriteLine("[7/7] Creating client...");
            var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
            var clientResp = await client.PostAsync("/api/clients", clientContent);

            if (clientResp.StatusCode == HttpStatusCode.Created || clientResp.StatusCode == HttpStatusCode.OK)
            {
                Console.WriteLine("✅ Client successfully created in MijnDiAd EPD");
            }
            else
            {
                var respBody = await clientResp.Content.ReadAsStringAsync();
                Console.WriteLine("❌ Client creation failed");
                Console.WriteLine("== Response Status: " + (int)clientResp.StatusCode + " ==");
                Console.WriteLine(respBody);
                throw new Exception("Client creation failed");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("❌ Exception: " + ex.Message);
            Environment.Exit(1);
        }
    }
}
