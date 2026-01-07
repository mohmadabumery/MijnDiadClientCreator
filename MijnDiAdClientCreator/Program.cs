using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace MijnDiAdClientCreator
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // =======================================
            // MODE 1: Refresh session (human login)
            // =======================================
            if (args.Length == 1 && args[0] == "refresh-session")
            {
                await RefreshSessionHumanAsync();
                return;
            }

            // =======================================
            // MODE 2: Create client (JSON payload)
            // =======================================
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

            string dynamicsJson = null;

            if (args.Length == 2 && args[0] == "--json")
                dynamicsJson = args[1];
            else if (args.Length == 1 && File.Exists(args[0]))
                dynamicsJson = await File.ReadAllTextAsync(args[0]);
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
                Console.WriteLine("Session cookie or XSRF token is missing.");
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

        // =======================================
        // Human-login session refresh
        // =======================================
        static async Task RefreshSessionHumanAsync()
        {
            var username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            var password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");

            if (new[] { username, password, tenant }.Any(string.IsNullOrWhiteSpace))
            {
                throw new Exception("Missing required environment variables for session refresh.");
            }

            using var playwright = await Playwright.CreateAsync();
            await using var browser = await playwright.Chromium.LaunchAsync(new()
            {
                Headless = false, // show browser for manual login
                SlowMo = 250
            });

            var context = await browser.NewContextAsync();
            var page = await context.NewPageAsync();

            await page.GotoAsync($"https://{tenant}.mijndiad.nl/");

            Console.WriteLine("🚨 Please log in manually in the browser, complete OTP if required, then press ENTER here.");
            Console.ReadLine();

            var cookies = await context.CookiesAsync();
            var session = cookies.FirstOrDefault(c => c.Name.EndsWith("_session"))?.Value;
            var xsrf = cookies.FirstOrDefault(c => c.Name == "XSRF-TOKEN")?.Value;

            await browser.CloseAsync();

            if (string.IsNullOrWhiteSpace(session) || string.IsNullOrWhiteSpace(xsrf))
            {
                Console.WriteLine("Failed to get session or XSRF. Login may have failed.");
                return;
            }

            // Output JSON for GitHub Actions
            Console.WriteLine(JsonSerializer.Serialize(new { session, xsrf }));
            Console.WriteLine("✅ Session refreshed successfully!");
        }
    }
}
