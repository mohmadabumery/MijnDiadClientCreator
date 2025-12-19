using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Missing JSON file argument");
            return;
        }

        string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";
        string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
        string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

        string jsonPath = args[0];
        if (!File.Exists(jsonPath))
        {
            Console.WriteLine($"File not found: {jsonPath}");
            return;
        }

        string clientJson = await File.ReadAllTextAsync(jsonPath);

        Console.WriteLine("Launching headless browser...");
        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true
        });

        var context = await browser.NewContextAsync();
        var page = await context.NewPageAsync();

        Console.WriteLine("[1/3] Navigating to login page...");
        await page.GotoAsync($"https://{tenant}.mijndiad.nl/login");

        // Fill login form
        Console.WriteLine("[2/3] Logging in...");
        await page.FillAsync("input[name=email]", username);
        await page.FillAsync("input[name=password]", password);

        // Generate TOTP code dynamically
        string totp = GenerateTOTP(totpSecret);
        await page.FillAsync("input[name=totp_code]", totp);

        // Submit the login form
        await page.ClickAsync("button[type=submit]");

        // Wait for navigation to dashboard / some element that indicates login success
        await page.WaitForSelectorAsync("text=Dashboard", new PageWaitForSelectorOptions { Timeout = 15000 });
        Console.WriteLine("✓ Logged in successfully!");

        // Get cookies for API
        var cookies = await context.CookiesAsync();
        string xsrf = null, session = null;
        foreach (var c in cookies)
        {
            if (c.Name == "XSRF-TOKEN") xsrf = c.Value;
            if (c.Name.EndsWith("_session")) session = c.Value;
        }

        if (string.IsNullOrEmpty(xsrf) || string.IsNullOrEmpty(session))
        {
            Console.WriteLine("❌ Failed to get session cookies");
            return;
        }

        Console.WriteLine("[3/3] Creating client via API...");

        // Use page.EvaluateAsync to POST client JSON with correct headers
        string script = @$"
            fetch('https://{tenant}.mijndiad.nl/api/clients', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': '{xsrf}',
                    'X-Requested-With': 'XMLHttpRequest'
                }},
                body: JSON.stringify({clientJson})
            }})
            .then(r => r.json())";

        var result = await page.EvaluateAsync<JsonElement>(script);
        Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine("✓ Client creation attempted");

        // Delete the processed file
        File.Delete(jsonPath);
        Console.WriteLine($"✓ Cleaned up file: {jsonPath}");
    }

    static string GenerateTOTP(string base32)
    {
        const int digits = 6;
        byte[] key = Base32Decode(base32);
        long timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        byte[] data = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(timestep));

        using var hmac = new System.Security.Cryptography.HMACSHA1(key);
        byte[] hash = hmac.ComputeHash(data);

        int offset = hash[^1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);

        return (binary % (int)Math.Pow(10, digits)).ToString($"D{digits}");
    }

    static byte[] Base32Decode(string input)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        string bits = "";

        foreach (char c in input.Trim('=').ToUpper())
            bits += Convert.ToString(chars.IndexOf(c), 2).PadLeft(5, '0');

        byte[] result = new byte[bits.Length / 8];
        for (int i = 0; i < result.Length; i++)
            result[i] = Convert.ToByte(bits.Substring(i * 8, 8), 2);

        return result;
    }
}
