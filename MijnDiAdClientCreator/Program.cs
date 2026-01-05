using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using OtpNet;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length < 2 || args[0] != "--json")
        {
            Console.WriteLine("Usage: dotnet run -- --json \"{...client JSON...}\"");
            return;
        }

        string clientJson = args[1];

        // Read environment variables
        string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        if (string.IsNullOrEmpty(tenant) || string.IsNullOrEmpty(username) ||
            string.IsNullOrEmpty(password) || string.IsNullOrEmpty(totpSecret))
        {
            Console.WriteLine("❌ Missing required environment variables.");
            return;
        }

        string baseUrl = $"https://{tenant}.mijndiad.nl";
        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler { CookieContainer = cookieContainer, UseCookies = true };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(baseUrl) };

        Console.WriteLine("== MijnDiAd Auto-Login & Client Creation ==");

        try
        {
            // Step 1: Fetch login page
            Console.WriteLine("[1/6] Fetching login page...");
            var loginPage = await client.GetAsync("/");
            loginPage.EnsureSuccessStatusCode();

            // Step 2: Extract CSRF token
            Console.WriteLine("[2/6] Extracting CSRF token...");
            string csrfToken = null;
            foreach (Cookie c in cookieContainer.GetCookies(new Uri(baseUrl)))
            {
                if (c.Name == "XSRF-TOKEN") csrfToken = c.Value;
            }

            if (string.IsNullOrEmpty(csrfToken))
                throw new Exception("❌ CSRF token not found");

            // Step 3: Log in
            Console.WriteLine("[3/6] Logging in...");
            var totp = new Totp(Base32Encoding.ToBytes(totpSecret));
            string otp = totp.ComputeTotp();

            var loginPayload = new
            {
                username,
                password,
                totp = otp
            };
            var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", csrfToken);
            client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");

            var loginResponse = await client.PostAsync("/login", loginContent);
            loginResponse.EnsureSuccessStatusCode();
            Console.WriteLine("  ✓ Login successful");

            // Step 4: Refresh Sanctum CSRF just before client creation
            Console.WriteLine("[4/6] Refreshing Sanctum CSRF...");
            var refreshCsrf = await client.GetAsync("/sanctum/csrf-cookie");
            refreshCsrf.EnsureSuccessStatusCode();

            // Extract refreshed XSRF token
            string xsrf = null;
            foreach (Cookie c in cookieContainer.GetCookies(new Uri(baseUrl)))
            {
                if (c.Name == "XSRF-TOKEN") xsrf = c.Value;
            }
            if (string.IsNullOrEmpty(xsrf))
                throw new Exception("❌ XSRF cookie missing after refresh");

            // Step 5: Prepare headers for client creation
            Console.WriteLine("[5/6] Extracting cookies and preparing headers...");
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrf);
            client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
            client.DefaultRequestHeaders.Add("Origin", baseUrl);
            client.DefaultRequestHeaders.Add("Referer", baseUrl);

            // Step 6: Create client
            Console.WriteLine("[6/6] Creating client...");
            var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
            var clientResponse = await client.PostAsync("/api/clients", clientContent);

            if (clientResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("✅ Client successfully created in MijnDiAd EPD");
            }
            else
            {
                string errorBody = await clientResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"❌ Client creation failed - Status: {clientResponse.StatusCode}");
                Console.WriteLine(errorBody);
                throw new Exception("Client creation failed");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            Environment.Exit(1);
        }
    }
}
