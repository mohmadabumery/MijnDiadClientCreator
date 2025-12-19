using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("== Dynamics → MijnDiAd Automation with Auto-Login ==");

            if (args.Length == 0)
            {
                Console.WriteLine("Please provide the path to the Dynamics JSON file as an argument.");
                return;
            }

            string jsonFilePath = args[0];
            if (!File.Exists(jsonFilePath))
            {
                Console.WriteLine($"File not found: {jsonFilePath}");
                return;
            }

            string dynamicsJson = await File.ReadAllTextAsync(jsonFilePath);

            // Read secrets from environment
            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(totpSecret))
            {
                Console.WriteLine("Missing credentials. Set MIJNDIAD_USERNAME, MIJNDIAD_PASSWORD, and MIJNDIAD_TOTP_SECRET as GitHub secrets.");
                return;
            }

            using var playwright = await Playwright.CreateAsync();
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true // headless mode for GitHub Actions
            });

            var context = await browser.NewContextAsync();
            var page = await context.NewPageAsync();

            Console.WriteLine("\n[1/3] Navigating to login page...");
            await page.GotoAsync($"https://{tenant}.mijndiad.nl/login");

            Console.WriteLine("[2/3] Filling login form...");
            await page.FillAsync("input[name='email']", username);
            await page.FillAsync("input[name='password']", password);

            // Generate TOTP dynamically
            string totp = GenerateTOTP(totpSecret);
            Console.WriteLine($"Generated TOTP: {totp}");
            await page.FillAsync("input[name='totp_code']", totp);

            await page.ClickAsync("button[type='submit']");

            // Wait for navigation / dashboard load
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            Console.WriteLine("✓ Login successful via browser simulation!");

            // Extract cookies
            var cookies = await context.CookiesAsync();
            string sessionCookie = null, xsrfToken = null;
            foreach (var cookie in cookies)
            {
                if (cookie.Name.EndsWith("_session")) sessionCookie = cookie.Value;
                if (cookie.Name == "XSRF-TOKEN") xsrfToken = cookie.Value;
            }

            if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            {
                Console.WriteLine("❌ Failed to retrieve session cookies after login.");
                return;
            }

            Console.WriteLine($"Session: {sessionCookie}");
            Console.WriteLine($"XSRF: {xsrfToken}");

            // Step 3: POST Dynamics JSON to API
            Console.WriteLine("\n[3/3] Sending Dynamics JSON to MijnDiAd API...");
            var httpClient = new System.Net.Http.HttpClient();
            httpClient.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            httpClient.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

            var content = new System.Net.Http.StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var apiUrl = $"https://{tenant}.mijndiad.nl/api/clients";
            var response = await httpClient.PostAsync(apiUrl, content);
            var result = await response.Content.ReadAsStringAsync();

            Console.WriteLine("MijnDiAd Response:");
            Console.WriteLine(result);

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("✓ Client created successfully!");
                File.Delete(jsonFilePath);
                Console.WriteLine($"✓ Cleaned up: {jsonFilePath}");
            }
            else
            {
                Console.WriteLine($"❌ Failed to create client. Status: {response.StatusCode}");
            }
        }

        // TOTP generation function
        static string GenerateTOTP(string base32Secret, int digits = 6, int period = 30)
        {
            byte[] secretBytes = Base32Decode(base32Secret);
            long counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / period;

            byte[] counterBytes = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                counterBytes[i] = (byte)(counter & 0xFF);
                counter >>= 8;
            }

            using var hmac = new HMACSHA1(secretBytes);
            byte[] hash = hmac.ComputeHash(counterBytes);

            int offset = hash[hash.Length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            int otp = binary % (int)Math.Pow(10, digits);
            return otp.ToString($"D{digits}");
        }

        static byte[] Base32Decode(string base32)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            string bits = "";
            foreach (char c in base32.ToUpper())
            {
                int index = alphabet.IndexOf(c);
                if (index < 0) continue;
                bits += Convert.ToString(index, 2).PadLeft(5, '0');
            }

            var bytes = new System.Collections.Generic.List<byte>();
            for (int i = 0; i + 8 <= bits.Length; i += 8)
            {
                bytes.Add(Convert.ToByte(bits.Substring(i, 8), 2));
            }
            return bytes.ToArray();
        }
    }
}
