using Microsoft.Playwright;
using System.Security.Cryptography;
using System.Text.Json;

class Program
{
    static async Task Main()
    {
        Console.WriteLine("== LoginAutomation ==");

        var user   = Env("MIJNDIAD_USERNAME");
        var pass   = Env("MIJNDIAD_PASSWORD");
        var tenant = Env("MIJNDIAD_TENANT");
        var totp   = Env("MIJNDIAD_TOTP_SECRET");

        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new() { Headless = true });

        var context = await browser.NewContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync($"https://{tenant}.mijndiad.nl/login");

        await page.FillAsync("input[name=email]", user);
        await page.FillAsync("input[name=password]", pass);
        await page.ClickAsync("button[type=submit]");

        await page.WaitForSelectorAsync("input[name=otp]");

        var otpCode = GenerateTotp(totp);
        await page.FillAsync("input[name=otp]", otpCode);
        await page.ClickAsync("button[type=submit]");

        await page.WaitForURLAsync($"https://{tenant}.mijndiad.nl/**");

        var cookies = await context.CookiesAsync();
        Directory.CreateDirectory("session");

        await File.WriteAllTextAsync(
            "session/session.json",
            JsonSerializer.Serialize(cookies, new JsonSerializerOptions { WriteIndented = true })
        );

        Console.WriteLine("✅ Login successful, session saved");
    }

    static string Env(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new Exception($"Missing env var {name}");

    static string GenerateTotp(string secret)
    {
        var key = Base32Decode(secret);
        var counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var data = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(data);

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(data);
        int offset = hash[^1] & 0x0F;

        int binary =
            ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);

        return (binary % 1_000_000).ToString("D6");
    }

    static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;

        foreach (var c in input.Trim('=').ToUpper())
        {
            buffer = (buffer << 5) | alphabet.IndexOf(c);
            bits += 5;

            if (bits >= 8)
            {
                bytes.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return bytes.ToArray();
    }
}
