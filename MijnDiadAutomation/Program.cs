using System;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace MijnDiadAutomation
{
    public class ClientData
    {
        public string Salutation { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Gender { get; set; }
        public string DateOfBirth { get; set; }
        public string DateOfIntake { get; set; }
        public string Email { get; set; }
        public string MobileNumber { get; set; }
        public string Reminder { get; set; }
        public string Confirmation { get; set; }
        public string InvoiceRelationId { get; set; }
        public string InvoiceSendMethod { get; set; }
        public string IsActive { get; set; }
        public AddressData Address { get; set; }
        public AddressData InvoiceAddress { get; set; }
        public string DifferentPostAddress { get; set; }
        public object[] ClientAttributes { get; set; }
        public object[] ClientGroupIds { get; set; }
        public string AllowDubbleEmail { get; set; }
    }

    public class AddressData
    {
        public string Country { get; set; }
        public string Zipcode { get; set; }
        public string HouseNumber { get; set; }
        public string Street { get; set; }
        public string City { get; set; }
    }

    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("No JSON input provided!");
                return 1;
            }

            var clientJson = args[0];
            ClientData client;
            try
            {
                client = JsonSerializer.Deserialize<ClientData>(clientJson);
            }
            catch
            {
                Console.WriteLine("Invalid JSON input!");
                return 1;
            }

            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");

            try
            {
                using var playwright = await Playwright.CreateAsync();
                var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
                {
                    Headless = true
                });

                var context = await browser.NewContextAsync();
                var page = await context.NewPageAsync();

                // Login
                await page.GotoAsync($"https://{tenant}.mijndiad.nl/login", new PageGotoOptions { Timeout = 60000 });
                await page.FillAsync("input[name=email]", username);
                await page.FillAsync("input[name=password]", password);
                await page.ClickAsync("button[type=submit]");

                // OTP screen
                var otpInput = page.Locator("input[name='totp'], input[id*='totp'], input[type='text'], input[type='number']");
                if (await otpInput.CountAsync() > 0)
                {
                    string totpCode = OtpGenerator.GenerateTOTP(totpSecret);
                    await otpInput.FillAsync(totpCode);
                    await page.ClickAsync("button[type=submit]");
                }

                // Wait until dashboard loads
                await page.WaitForURLAsync($"**/{tenant}/dashboard", new PageWaitForURLOptions { Timeout = 60000 });

                // Navigate to client creation page
                await page.GotoAsync($"https://{tenant}.mijndiad.nl/clients/new");

                // Fill client form
                await page.FillAsync("input[name=firstname]", client.Firstname);
                await page.FillAsync("input[name=lastname]", client.Lastname);
                await page.FillAsync("input[name=email]", client.Email);
                await page.FillAsync("input[name=zipcode]", client.Address.Zipcode);
                await page.FillAsync("input[name=street]", client.Address.Street);
                await page.FillAsync("input[name=city]", client.Address.City);
                // Add more fields as needed...

                await page.ClickAsync("button[type=submit]");

                Console.WriteLine(JsonSerializer.Serialize(new { status = "success", message = "Client created!" }));
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(JsonSerializer.Serialize(new { status = "error", message = ex.Message }));
                return 1;
            }
        }
    }

    public static class OtpGenerator
    {
        public static string GenerateTOTP(string secret)
        {
            var bytes = Base32.Base32Encoding.ToBytes(secret);
            var totp = new OtpNet.Totp(bytes);
            return totp.ComputeTotp();
        }
    }
}
