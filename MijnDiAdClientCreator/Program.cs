using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;
using OtpNet;

namespace MijnDiAdClientCreator
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // ================================
            // MODE 1: Refresh session
            // ================================
            if (args.Length == 1 && args[0] == "refresh-session")
            {
                await RefreshSessionAsync();
                return;
            }

            // ================================
            // MODE 2: Create client
            // ================================
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

            string dynamicsJson;

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

            var session = Environment.GetEnvironmentVariable("MIJNDIAD_SESSION");
            var xsrf = Environment.GetEnvironmentVariable("MIJNDIAD_XSRF");
            var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");

            if (string.IsNullOrWhiteSpace(session) || string.IsNullOrWhiteSpace(xsrf))
            {
                Console.WriteLine("Missing MIJNDIAD_SESSION or MIJNDIAD_XSRF.");
                return;
            }

            using var handler = new HttpClientHandler { UseCookies = false };
            using var client = new HttpClient(handler);

            client.DefaultRequestHeaders.Add("x-csrf-token", xsrf);
            client.DefaultRequestHeaders.Add(
                "Cookie",
                $"{tenant}_session={session}; XSRF-TOKEN={xsrf}"
            );

            var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var url = $"https://{tenant}.mijndiad.nl/api/clients";

            var response = await client.PostAsync(url, content);
            var result = await response.Content.ReadAsStringAsync();

            Console.WriteLine("== MijnDiAd Response ==");
            Console.WriteLine(result);
        }

        // =====================================================
        // SESSION REFRESH (Playwright + TOTP)
        // =====================================================
        static async Task RefreshSessionAsync()
        {
            var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
            var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

            if (new[] { username, password, tenant, totpSecret }.Any(string.IsNullOrWhiteSpace))
                throw new Exception("Missing environment variables for login.");

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

            var totp = new Totp(Base32Encoding.ToBytes(totpSecret));
            var otpCode = totp.ComputeTotp();

            await page.WaitForSelectorAsync("input[name=otp]");
            await page.FillAsync("input[name=otp]", otpCode);
            await page.ClickAsync("button[type=submit]");

            await page.WaitForURLAsync("**/dashboard**");

            var cookies = await context.CookiesAsync();

            var session = cookies.First(c => c.Name.EndsWith("_session")).Value;
            var xsrf = cookies.First(c => c.Name == "XSRF-TOKEN").Value;

            // Output JSON ONLY (used by GitHub Actions)
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                session,
                xsrf
            }));
        }
    }
}
