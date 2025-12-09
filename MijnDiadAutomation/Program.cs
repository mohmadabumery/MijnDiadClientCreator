using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

            if (args.Length == 0)
            {
                Console.WriteLine("Please provide the path to the Dynamics JSON file as an argument.");
                return;
            }

            string jsonFilePath = args[0];
            if (!File.Exists(jsonFilePath))
            {
                Console.WriteLine($"File not found: {jsonFilePath}");
                return;
            }

            string dynamicsJson = await File.ReadAllTextAsync(jsonFilePath);

            // Read secrets from environment (GitHub Actions)
            string sessionCookie = Environment.GetEnvironmentVariable("MIJNDIAD_SESSION");
            string xsrfToken = Environment.GetEnvironmentVariable("MIJNDIAD_XSRF");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(sessionCookie) || string.IsNullOrWhiteSpace(xsrfToken))
            {
                Console.WriteLine("Session cookie or XSRF token is missing. Set them as GitHub secrets.");
                return;
            }

            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

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
    }
}
