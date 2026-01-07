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
            
            // Detect direct JSON input
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

            // Read secrets from GitHub or environment
            string sessionCookie = Environment.GetEnvironmentVariable("MIJNDIAD_SESSION");
            string xsrfToken = Environment.GetEnvironmentVariable("MIJNDIAD_XSRF");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";
            string questionnaireIds = Environment.GetEnvironmentVariable("MIJNDIAD_QUESTIONNAIRE_IDS") ?? "5"; // Default to questionnaire 5

            if (string.IsNullOrWhiteSpace(sessionCookie) || string.IsNullOrWhiteSpace(xsrfToken))
            {
                Console.WriteLine("Session cookie or XSRF token is missing.");
                return;
            }

            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

            // Step 1: Create the client
            var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var url = $"https://{tenant}.mijndiad.nl/api/clients";
            
            try
            {
                Console.WriteLine("\n== Step 1: Creating Client ==");
                var response = await client.PostAsync(url, content);
                var result = await response.Content.ReadAsStringAsync();
                
                Console.WriteLine("MijnDiAd Client Creation Response:");
                Console.WriteLine(result);

                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Error: Client creation failed with status {response.StatusCode}");
                    return;
                }

                // Parse the response to get client ID and email
                var jsonResponse = JsonDocument.Parse(result);
                var clientData = jsonResponse.RootElement.GetProperty("data");
                int clientId = clientData.GetProperty("id").GetInt32();
                string clientEmail = clientData.GetProperty("email").GetString();

                Console.WriteLine($"\n✓ Client created successfully!");
                Console.WriteLine($"  Client ID: {clientId}");
                Console.WriteLine($"  Email: {clientEmail}");

                // Step 2: Send questionnaires
                await SendQuestionnaires(client, tenant, xsrfToken, clientId, clientEmail, questionnaireIds);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        static async Task SendQuestionnaires(HttpClient client, string tenant, string xsrfToken, int clientId, string clientEmail, string questionnaireIdsStr)
        {
            Console.WriteLine("\n== Step 2: Sending Questionnaires ==");

            // Parse questionnaire IDs (comma-separated, e.g., "5,7")
            var questionnaireIds = questionnaireIdsStr.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(id => int.Parse(id.Trim()))
                .ToArray();

            // Build the payload based on your network log
            var payload = new
            {
                client_id = clientId,
                questionnaire_ids = questionnaireIds,
                send_to_client = 1,
                email = clientEmail,
                client_relation_id = (string)null,
                email_data = new
                {
                    use_custom = false,
                    concept_id = (string)null,
                    subject = "",
                    content = "",
                    ics = "0",
                    questionnaire_ids = new int[0],
                    attachments = new object[0],
                    client_agreements = new object[0],
                    client_documents = new object[0],
                    client_files = new object[0],
                    concept_attachments = new object[0],
                    documents = new object[0],
                    email_template_id = (string)null,
                    email_type = "EMAIL_TEMPLATE_INVITE_CLIENT_QUESTIONNAIRE",
                    general_files = new object[0],
                    regarding = (string)null,
                    use_custom = false
                },
                notification_date = (string)null,
                plan_questionnaire = false,
                _method = (string)null
            };

            var jsonPayload = JsonSerializer.Serialize(payload);
            var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
            
            var url = $"https://{tenant}.mijndiad.nl/api/client-questionnaires";

            try
            {
                // Update headers for this request
                client.DefaultRequestHeaders.Remove("x-csrf-token");
                client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
                
                var response = await client.PostAsync(url, content);
                var result = await response.Content.ReadAsStringAsync();

                Console.WriteLine("Questionnaire Send Response:");
                Console.WriteLine(result);

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"\n✓ Questionnaires sent successfully to {clientEmail}!");
                    Console.WriteLine($"  Questionnaire IDs: {string.Join(", ", questionnaireIds)}");
                }
                else
                {
                    Console.WriteLine($"\n✗ Failed to send questionnaires. Status: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending questionnaires: {ex.Message}");
            }
        }
    }
}
