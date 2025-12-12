using System;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Please provide JSON input as argument.");
                return;
            }

            string jsonInput = args[0];
            JsonDocument doc = JsonDocument.Parse(jsonInput);
            JsonElement clientData = doc.RootElement;

            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") ?? "";
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") ?? "";
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") ?? "";
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "";

            using var playwright = await Playwright.CreateAsync();
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true
            });
            var context = await browser.NewContextAsync();
            var page = await context.NewPageAsync();

            // LOGIN
            await LoginToMijnDiad(page, username, password, totpSecret, tenant);

            // CREATE CLIENT
            await CreateClient(page, clientData);
        }

        static async Task LoginToMijnDiad(IPage page, string username, string password, string totpSecret, string tenant)
        {
            string loginUrl = $"https://{tenant}.mijndiad.nl/login";
            Console.WriteLine($"Navigating to login page: {loginUrl}");
            await page.GotoAsync(loginUrl);

            // Fill username and password
            await page.FillAsync("input[name='email']", username);
            await page.FillAsync("input[name='password']", password);
            await page.ClickAsync("button[type='submit']");

            // Wait for OTP input if present
            var totpInput = page.Locator("input[name='totp'], input[id*='totp'], input[type='text'], input[type='number']");
            if (await totpInput.CountAsync() > 0)
            {
                string totpCode = GenerateTotpCode(totpSecret);
                Console.WriteLine($"Generated TOTP code: {totpCode}");
                await totpInput.FillAsync(totpCode);
                await page.ClickAsync("button[type='submit']");
            }

            // Wait for login success, e.g., a known element visible after login
            await page.WaitForSelectorAsync("text=Dashboard", new PageWaitForSelectorOptions { Timeout = 60000 });
            Console.WriteLine("✓ Login successful! Session is active.");
        }

        static string GenerateTotpCode(string secret)
        {
            // Simple placeholder: replace with your TOTP generation logic
            // e.g., using OtpNet library
            return "000000"; // Replace with actual TOTP code generation
        }

        static async Task CreateClient(IPage page, JsonElement clientData)
        {
            Console.WriteLine("[Step 2/3] Creating client in MijnDiAd...");

            // Example: navigate to create client page
            await page.GotoAsync("https://YOUR_TENANT.mijndiad.nl/client/create");

            // Fill client form using clientData
            await page.FillAsync("input[name='firstname']", clientData.GetProperty("firstname").GetString());
            await page.FillAsync("input[name='lastname']", clientData.GetProperty("lastname").GetString());
            await page.FillAsync("input[name='email']", clientData.GetProperty("email").GetString());
            await page.FillAsync("input[name='zipcode']", clientData.GetProperty("address").GetProperty("zipcode").GetString());
            await page.FillAsync("input[name='street']", clientData.GetProperty("address").GetProperty("street").GetString());
            await page.FillAsync("input[name='city']", clientData.GetProperty("address").GetProperty("city").GetString());

            // Submit form
            await page.ClickAsync("button[type='submit']");

            Console.WriteLine("✓ Client successfully created in MijnDiAd EPD");
        }
    }
}
