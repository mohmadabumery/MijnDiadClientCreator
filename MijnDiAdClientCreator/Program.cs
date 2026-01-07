using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Playwright;
using OtpNet;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // ================================
            // MODE 1: Refresh session (OTP)
            // ================================
            if (args.Length == 1 && args[0] == "refresh-session")
            {
                await RefreshSessionAsync();
                return;
            }

            // ================================
            // MODE 2: Create client (existing)
            // ================================
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

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

            string sessionCookie = Environment.GetEnvironmentVariable("MIJNDIAD_SESSION");
            string xsrfToken = Environment.GetEnvironmentVariable("MIJNDIAD_XSRF");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");

            if (string.IsNullOrWhiteSpace(sessionCookie) || string.IsNullOrWhiteSpace(xsrfToken))
            {
                Console.WriteLine("Session cookie or XSRF token is missing.");
                return;
            }

            using var handler = new HttpClientHandler { UseCookies = false };
            using var client = new HttpClient(handler);

            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            client.DefaultRequestHeaders.Add(
                "Cookie",
                $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}"
            );

            var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var url = $"https://{tenant}.mijndiad.nl/api/clients";

            try
            {
                var response = await client.PostAsync(url, content);
                var result = await response.Content.ReadAsStringAsync();

                Console.WriteLine("\n== MijnDiAd Response ==");
                Console.WriteLine(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending request: {ex.Message}");
            }
        }

        // =====================================================
        // SESSION REFRESH (Playwright + OTP / TOTP)
        // =====================================================
        static async Task RefreshSessionAsync()
        {
            var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
            var totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");

            if (new[] { username, password, tenant, totpSecret }.Any(string.IsNullOrWhiteSpace))
            {
                throw new Exception("Missing required environment variables for session refresh.");
            }

            using var playwright = await Playwright.CreateAsync();
            await using var browser = await playwright.Chromium.LaunchAsync(new()
            {
                Headless = true
            });

            var context = await browser.NewContextAsync();
            var page = await context.NewPageAsync();

            await page.GotoAsync($"https://{tenant}.mijndiad.nl/login");

            // Login step
            await page.FillAsync("input[type=email]", username);
            await page.FillAsync("input[type=password]", password);
            await page.ClickAsync("button[type=submit]");

            // OTP step
            var totp = new Totp(Base32Encoding.ToBytes(totpSecret));
            var otpCode = totp.ComputeTotp();

            await page.WaitForSelectorAsync("input[name=otp]");
            await page.FillAsync("input[name=otp]", otpCode);
            await page.ClickAsync("button[type=submit]");

            // Wait for successful login
            await page.WaitForURLAsync("**/dashboard**");

            var cookies = await context.CookiesAsync();

            var session = cookies.First(c => c.Name.EndsWith("_session")).Value;
            var xsrf = cookies.First(c => c.Name == "XSRF-TOKEN").Value;

            // IMPORTANT: output JSON only (used by GitHub Actions)
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                session,
                xsrf
            }));
        }
    }
}
