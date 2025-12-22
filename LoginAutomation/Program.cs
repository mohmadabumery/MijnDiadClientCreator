using Microsoft.Playwright;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

class Program
{
    static async Task Main()
    {
        Console.WriteLine("== LoginAutomation with OTP ==");

        var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        var tenant   = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var totpKey  = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new()
        {
            Headless = true
        });

        var context = await browser.NewContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync($"https://{tenant}.mijndiad.nl/login");

        // Step 1: username + password
        await page.FillAsync("input[name=email]", username);
        await page.FillAsync("input[name=password]", password);
        await page.ClickAsync("button[type=submit]");

        // Step 2: wait for OTP field
        await page.WaitForSelectorAsync("input[name=otp]");

        var otp = GenerateTotp(totpKey);
        Console.WriteLine($"Generated OTP: {otp}");

        await page.FillAsync("input[name=otp]", otp);
        await page.ClickAsync("button[type=submit]");

        // Step 3: successful login redirect
        await page.WaitForURLAsync($"https://{tenant}.mijndiad.nl/**");

        var cookies = await context.CookiesAsync();
        var xsrf = cookies.First(c => c.Name == "XSRF-TOKEN").Value;

        Directory.CreateDirectory("session");

        await File.WriteAllTextAsync(
            "session/session.json",
            JsonSerializer.Serialize(new
            {
                cookies,
                xsrf,
                createdAt = DateTime.UtcNow
            }, new JsonSerializerOptions { WriteIndented = true })
        );

        Console.WriteLine("✅ Login + OTP successful, session saved");
    }

    // RFC 6238 TOTP
    static string GenerateTotp(string secret)
    {
        var key = Base32Decode(secret);
        var timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var data = BitConverter.GetBytes(timestep);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(data);

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(data);

        int offset = hash[^1] & 0x0F;
        int binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);

        return (binary % 1_000_000).ToString("D6");
    }

    static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();

        int buffer = 0, bitsLeft = 0;
        foreach (char c in input.TrimEnd('=').ToUpperInvariant())
        {
            buffer <<= 5;
            buffer |= alphabet.IndexOf(c);
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bytes.Add((byte)(buffer >> (bitsLeft - 8)));
                bitsLeft -= 8;
            }
        }
        return bytes.ToArray();
    }
}
