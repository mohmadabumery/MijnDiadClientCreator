using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;
using System.Net.Http;
using System.Linq;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

            // Parse JSON input
            string dynamicsJson = null;
            if (args.Length == 2 && args[0] == "--json")
            {
                dynamicsJson = args[1];
            }
            else if (args.Length == 1 && File.Exists(args[0]))
            {
                dynamicsJson = await File.ReadAllTextAsync(args[0]);
            }
            else
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("dotnet run -- --json \"{ ... }\"");
                Console.WriteLine("or");
                Console.WriteLine("dotnet run path/to/file.json");
                return;
            }

            // Read credentials from GitHub secrets
            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("❌ Missing credentials. Set MIJNDIAD_USERNAME and MIJNDIAD_PASSWORD as GitHub secrets.");
                return;
            }

            // Step 1: Login using Playwright
            Console.WriteLine("\n[Step 1/3] Logging in to MijnDiAd...");
            var (sessionCookie, xsrfToken) = await LoginToMijnDiad(username, password, totpSecret, tenant);

            if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            {
                Console.WriteLine("❌ Login failed. Could not retrieve session cookies.");
                return;
            }

            Console.WriteLine("✓ Login successful! Got fresh session cookies.");

            // Step 2: Post client data to MijnDiAd API
            Console.WriteLine("\n[Step 2/3] Creating client in MijnDiAd...");
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

            var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var url = $"https://{tenant}.mijndiad.nl/api/clients";

            try
            {
                var response = await client.PostAsync(url, content);
                var result = await response.Content.ReadAsStringAsync();

                Console.WriteLine("\n[Step 3/3] MijnDiAd API Response:");
                Console.WriteLine(result);

                if (response.IsSuccessStatusCode)
                    Console.WriteLine("\n✓✓✓ SUCCESS! Client created in MijnDiAd EPD ✓✓✓");
                else
                    Console.WriteLine($"\n❌ Failed to create client. Status: {response.StatusCode}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error sending request: {ex.Message}");
            }
        }

        // ---------------- Playwright Login ----------------
        static async Task<(string sessionCookie, string xsrfToken)> LoginToMijnDiad(string username, string password, string totpSecret, string tenant)
        {
            using var playwright = await Playwright.CreateAsync();
            var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
            var context = await browser.NewContextAsync();
            context.SetDefaultTimeout(60000); // 60s timeout
            var page = await context.NewPageAsync();

            string loginUrl = $"https://{tenant}.mijndiad.nl/login";
            Console.WriteLine($"Navigating to login page: {loginUrl}");
            await page.GotoAsync(loginUrl, new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle });

            // Optional: take screenshot for debugging
            await page.ScreenshotAsync(new PageScreenshotOptions { Path = "login_page.png" });

            // Fill login fields
            await page.FillAsync("input[name=email]", username);
            await page.FillAsync("input[name=password]", password);

            if (!string.IsNullOrEmpty(totpSecret))
            {
                string totpCode = GenerateTOTP(totpSecret);
                Console.WriteLine($"Generated TOTP: {totpCode}");
                await page.FillAsync("input[name=totp]", totpCode);
            }

            await page.ClickAsync("button[type=submit]");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            // Optional: screenshot after login
            await page.ScreenshotAsync(new PageScreenshotOptions { Path = "after_login.png" });

            var cookies = await context.CookiesAsync();
            string sessionCookie = cookies.FirstOrDefault(c => c.Name == $"{tenant}_session")?.Value;
            string xsrfToken = cookies.FirstOrDefault(c => c.Name == "XSRF-TOKEN")?.Value;

            await browser.CloseAsync();
            return (sessionCookie, xsrfToken);
        }

        // ---------------- TOTP Generator ----------------
        static string GenerateTOTP(string base32Secret, int digits = 6, int period = 30)
        {
            byte[] secretBytes = Base32Decode(base32Secret);
            long epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long counter = epoch / period;

            byte[] counterBytes = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                counterBytes[i] = (byte)(counter & 0xFF);
                counter >>= 8;
            }

            using var hmac = new System.Security.Cryptography.HMACSHA1(secretBytes);
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
            for (int i = 0; i < bits.Length; i += 8)
            {
                int length = Math.Min(8, bits.Length - i);
                string segment = bits.Substring(i, length);
                if (segment.Length == 8)
                    bytes.Add(Convert.ToByte(segment, 2));
            }

            return bytes.ToArray();
        }
    }
}
