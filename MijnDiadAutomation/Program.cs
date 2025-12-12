using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

            // Parse input JSON
            string dynamicsJson = null;
            if (args.Length == 2 && args[0] == "--json")
                dynamicsJson = args[1];
            else if (args.Length == 1 && File.Exists(args[0]))
                dynamicsJson = await File.ReadAllTextAsync(args[0]);
            else
            {
                Console.WriteLine("Usage: dotnet run -- --json \"{ ... }\" or dotnet run path/to/file.json");
                return;
            }

            // Read credentials from environment
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
            using var client = new System.Net.Http.HttpClient();
            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

            var content = new System.Net.Http.StringContent(dynamicsJson, Encoding.UTF8, "application/json");
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
                {
                    Console.WriteLine($"\n❌ Failed to create client. Status: {response.StatusCode}");
                    Environment.Exit(1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error sending request: {ex.Message}");
                Environment.Exit(1);
            }
        }

        static async Task<(string sessionCookie, string xsrfToken)> LoginToMijnDiad(
            string username, string password, string totpSecret, string tenant)
        {
            using var playwright = await Playwright.CreateAsync();

            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true,  // false for debugging
                SlowMo = 50
            });

            var context = await browser.NewContextAsync();
            var page = await context.NewPageAsync();

            string loginUrl = $"https://{tenant}.mijndiad.nl/login";
            Console.WriteLine($"Navigating to login page: {loginUrl}");
            await page.GotoAsync(loginUrl, new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle });

            // Fill username and password
            await page.FillAsync("input[name='email'], input[type='email']", username);
            await page.FillAsync("input[name='password'], input[type='password']", password);

            // Handle TOTP
            if (!string.IsNullOrWhiteSpace(totpSecret))
            {
                string totpCode = GenerateTOTP(totpSecret);
                Console.WriteLine($"Generated TOTP code: {totpCode}");

                await page.Locator("input[name='totp'], input[id*='totp'], input[type='text'], input[type='number']")
                          .WaitForAsync(new LocatorWaitForOptions { Timeout = 60000 });

                await page.FillAsync("input[name='totp'], input[id*='totp'], input[type='text'], input[type='number']", totpCode);
            }

            await page.ClickAsync("button[type='submit'], button:has-text('Login')");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            var cookies = await context.CookiesAsync();
            string sessionCookie = cookies.FirstOrDefault(c => c.Name.EndsWith("_session"))?.Value;
            string xsrfToken = cookies.FirstOrDefault(c => c.Name == "XSRF-TOKEN")?.Value;

            return (sessionCookie, xsrfToken);
        }

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
            for (int i = 0; i < bits.Length; i += 8)
            {
                if (i + 8 <= bits.Length)
                    bytes.Add(Convert.ToByte(bits.Substring(i, 8), 2));
            }
            return bytes.ToArray();
        }
    }
}
