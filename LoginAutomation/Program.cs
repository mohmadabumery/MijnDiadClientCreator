using System.Text.Json;
using Microsoft.Playwright;

class Program
{
    public static async Task Main()
    {
        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
        string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(totpSecret))
        {
            Console.WriteLine("Missing secrets!");
            return;
        }

        using var playwright = await Playwright.CreateAsync();
        var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
        var context = await browser.NewContextAsync();
        var page = await context.NewPageAsync();

        Console.WriteLine("Navigating to login page...");
        await page.GotoAsync($"https://{tenant}.mijndiad.nl/login");

        // Fill username/password
        await page.FillAsync("input[name=email]", username);
        await page.FillAsync("input[name=password]", password);

        // Fill TOTP
        string totpCode = GenerateTOTP(totpSecret);
        await page.FillAsync("input[name=totp_code]", totpCode);

        await page.ClickAsync("button[type=submit]");
        await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Get session cookies and XSRF token
        var cookies = await context.CookiesAsync();
        var xsrfToken = await page.EvaluateAsync<string>("() => document.querySelector('meta[name=\"csrf-token\"]').getAttribute('content')");

        var sessionData = new
        {
            cookies,
            xsrfToken
        };

        string json = JsonSerializer.Serialize(sessionData, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync("session/session.json", json);

        Console.WriteLine("✓ Session saved successfully!");
        await browser.CloseAsync();
    }

    static string GenerateTOTP(string secret)
    {
        // Use the same TOTP function from previous code
        byte[] secretBytes = Base32Decode(secret);
        long epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long counter = epoch / 30;

        byte[] counterBytes = new byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        using var hmac = new System.Security.Cryptography.HMACSHA1(secretBytes);
        byte[] hash = hmac.ComputeHash(counterBytes);

        int offset = hash[hash.Length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   | (hash[offset + 3] & 0xFF);

        int otp = binary % 1000000;
        return otp.ToString("D6");
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
