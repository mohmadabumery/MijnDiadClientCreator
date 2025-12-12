using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("== Dynamics → MijnDiAd Automation (Playwright) ==");

            // Get JSON input
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

            // Read credentials from environment
            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(totpSecret))
            {
                Console.WriteLine("❌ Missing credentials or TOTP secret.");
                return;
            }

            Console.WriteLine("[Step 1/3] Launching browser and logging in...");

            using var playwright = await Playwright.CreateAsync();
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true // set false for debugging
            });

            var context = await browser.NewContextAsync();
            var page = await context.NewPageAsync();

            // Navigate to login page
            var loginUrl = $"https://{tenant}.mijndiad.nl/login";
            await page.GotoAsync(loginUrl);

            // Fill credentials
            await page.FillAsync("input[name='email']", username);
            await page.FillAsync("input[name='password']", password);

            // Generate TOTP code
            string totpCode = GenerateTOTP(totpSecret);
            Console.WriteLine($"  Generated TOTP code: {totpCode}");
            await page.FillAsync("input[name='totp']", totpCode);

            // Submit login form
            await page.ClickAsync("button[type='submit']");

            // Wait for navigation to dashboard or cookies
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            // Extract session cookies
            var cookies = await context.CookiesAsync();
            string sessionCookie = null;
            string xsrfToken = null;
            foreach (var c in cookies)
            {
                if (c.Name.EndsWith("_session"))
                    sessionCookie = c.Value;
                if (c.Name == "XSRF-TOKEN")
                    xsrfToken = c.Value;
            }

            if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            {
                Console.WriteLine("❌ Failed to extract session cookies.");
                return;
            }

            Console.WriteLine("✓ Login successful, session cookies obtained.");

            // Step 2: Post client data
            Console.WriteLine("[Step 2/3] Creating client in MijnDiAd...");
            var apiUrl = $"https://{tenant}.mijndiad.nl/api/clients";

            var response = await page.Request.PostAsync(apiUrl, new()
            {
                Headers = new()
                {
                    ["x-csrf-token"] = xsrfToken,
                    ["Cookie"] = $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}"
                },
                DataString = dynamicsJson,
                ContentType = "application/json"
            });

            var resultText = await response.TextAsync();
            Console.WriteLine("[Step 3/3] MijnDiAd API Response:");
            Console.WriteLine(resultText);

            if (response.Status == 200 || response.Status == 201)
            {
                Console.WriteLine("✓✓✓ SUCCESS! Client created in MijnDiAd EPD ✓✓✓");
            }
            else
            {
                Console.WriteLine($"❌ Failed to create client. Status: {response.Status}");
                Environment.Exit(1);
            }

            await browser.CloseAsync();
        }

        static string GenerateTOTP(string base32Secret, int digits = 6, int period = 30)
        {
            // Base32 decode
            var secretBytes = Base32Decode(base32Secret);

            long epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long counter = epoch / period;

            byte[] counterBytes = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                counterBytes[i] = (byte)(counter & 0xFF);
                counter >>= 8;
            }

            using var hmac = new System.Security.Cryptography.HMACSHA1(secretBytes);
            var hash = hmac.ComputeHash(counterBytes);

            int offset = hash[^1] & 0x0F;
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

            foreach (var c in base32.ToUpper())
            {
                int idx = alphabet.IndexOf(c);
                if (idx < 0) continue;
                bits += Convert.ToString(idx, 2).PadLeft(5, '0');
            }

            var bytes = new System.Collections.Generic.List<byte>();
            for (int i = 0; i < bits.Length; i += 8)
            {
                int len = Math.Min(8, bits.Length - i);
                string segment = bits.Substring(i, len);
                if (segment.Length == 8)
                    bytes.Add(Convert.ToByte(segment, 2));
            }

            return bytes.ToArray();
        }
    }
}
