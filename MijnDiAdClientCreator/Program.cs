using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
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
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(sessionCookie) || string.IsNullOrWhiteSpace(xsrfToken))
            {
                Console.WriteLine("Session cookie or XSRF token is missing.");
                return;
            }

            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

            var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var url = $"https://{tenant}.mijndiad.nl/api/clients";

            try
            {
                // 1️⃣ Create client
                var response = await client.PostAsync(url, content);
                var result = await response.Content.ReadAsStringAsync();
                Console.WriteLine("\n== MijnDiAd Client Response ==");
                Console.WriteLine(result);

                // Parse client ID
                using var doc = JsonDocument.Parse(result);
                int clientId = doc.RootElement.GetProperty("id").GetInt32();
                Console.WriteLine($"Client ID: {clientId}");

                // 2️⃣ Send questionnaires
                int[] questionnaireIds = { 15, 4 };
                foreach (var qId in questionnaireIds)
                {
                    var payload = new
                    {
                        client_id = clientId,
                        questionnaire_id = qId,
                        send_method = "email"
                    };

                    var qResponse = await client.PostAsJsonAsync(
                        $"https://{tenant}.mijndiad.nl/api/client-questionnaires",
                        payload
                    );

                    var qResult = await qResponse.Content.ReadAsStringAsync();
                    Console.WriteLine($"\n== Questionnaire {qId} Response ==");
                    Console.WriteLine(qResult);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending request: {ex.Message}");
            }
        }
    }
}
