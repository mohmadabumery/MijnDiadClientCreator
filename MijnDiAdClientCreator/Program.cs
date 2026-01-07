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

            // Detect JSON input
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

            // Read secrets
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
            var clientUrl = $"https://{tenant}.mijndiad.nl/api/clients";

            try
            {
                // 1️⃣ Create client
                var response = await client.PostAsync(clientUrl, content);
                var result = await response.Content.ReadAsStringAsync();
                Console.WriteLine("\n== MijnDiAd Client Response ==");
                Console.WriteLine(result);

                // 2️⃣ Parse client ID and email
                using var doc = JsonDocument.Parse(result);
                int clientId = doc.RootElement
                                  .GetProperty("data")
                                  .GetProperty("client")
                                  .GetProperty("id")
                                  .GetInt32();
                string clientEmail = JsonDocument.Parse(dynamicsJson)
                                     .RootElement
                                     .GetProperty("email")
                                     .GetString();

                Console.WriteLine($"Client ID: {clientId}");
                Console.WriteLine($"Client Email: {clientEmail}");

                // 3️⃣ Send questionnaires via email
                int[] questionnaireIds = { 5, 4 }; // Horizon and Medical
                foreach (var qId in questionnaireIds)
                {
                    var payload = new
                    {
                        client_id = clientId,
                        questionnaire_id = qId,
                        send_method = "email",
                        email = clientEmail
                    };

                    var qResponse = await client.PostAsJsonAsync(
                        $"https://{tenant}.mijndiad.nl/api/client-questionnaires",
                        payload
                    );

                    var qResult = await qResponse.Content.ReadAsStringAsync();
                    Console.WriteLine($"\n== Questionnaire {qId} Response ==");
                    Console.WriteLine(qResult);
                }

                // 4️⃣ List sent questionnaires for verification
                var listResponse = await client.GetAsync(
                    $"https://{tenant}.mijndiad.nl/api/clients/{clientId}/questionnaires?sort=updated_at|desc&page=1&per_page=25"
                );
                var listJson = await listResponse.Content.ReadAsStringAsync();
                Console.WriteLine("\n== Sent Questionnaires List ==");
                Console.WriteLine(listJson);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending request: {ex.Message}");
            }
        }
    }
}
