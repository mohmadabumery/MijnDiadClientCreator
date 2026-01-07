using Microsoft.Playwright;
using OtpNet;
using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

class RefreshSession
{
    public static async Task Run()
    {
        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        if (new[] { username, password, tenant, totpSecret }.Any(string.IsNullOrWhiteSpace))
            throw new Exception("Missing required environment variables.");

        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new()
        {
            Headless = true
        });

        var context = await browser.NewContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync($"https://{tenant}.mijndiad.nl/login");

        await page.FillAsync("input[type=email]", username);
        await page.FillAsync("input[type=password]", password);
        await page.ClickAsync("button[type=submit]");

        // OTP step
        var totp = new Totp(Base32Encoding.ToBytes(totpSecret));
        var otpCode = totp.ComputeTotp();

        await page.WaitForSelectorAsync("input[name=otp]");
        await page.FillAsync("input[name=otp]", otpCode);
        await page.ClickAsync("button[type=submit]");

        await page.WaitForURLAsync("**/dashboard**");

        var cookies = await context.CookiesAsync();

        var session = cookies.First(c => c.Name.EndsWith("_session")).Value;
        var xsrf = cookies.First(c => c.Name == "XSRF-TOKEN").Value;

        Console.WriteLine(JsonSerializer.Serialize(new
        {
            session,
            xsrf
        }));
    }
}
