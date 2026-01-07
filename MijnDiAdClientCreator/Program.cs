using System;
using System.IO;
using System.Linq;
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
            string questionnaireIds = Environment.GetEnvironmentVariable("MIJNDIAD_QUESTIONNAIRE_IDS") ?? "5";

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
                
                // The structure is data.client, not just data
                var dataObject = jsonResponse.RootElement.GetProperty("data");
                var clientData = dataObject.GetProperty("client");
                
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

            // Parse questionnaire IDs (comma-separated, e.g., "5,4")
            var questionnaireIds = questionnaireIdsStr
                .Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(id => int.Parse(id.Trim()))
                .ToArray();

            Console.WriteLine($"Will send {questionnaireIds.Length} questionnaire(s) separately: {string.Join(", ", questionnaireIds)}");

            int successCount = 0;
            int failCount = 0;

            // Send each questionnaire separately
            for (int i = 0; i < questionnaireIds.Length; i++)
            {
                var questionnaireId = questionnaireIds[i];
                Console.WriteLine($"\n--- Sending Questionnaire {i + 1}/{questionnaireIds.Length} (ID: {questionnaireId}) ---");

                // Build the payload for a single questionnaire
                var payload = new
                {
                    client_id = clientId,
                    questionnaire_ids = new int[] { questionnaireId }, // Single questionnaire
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
                        regarding = (string)null
                    },
                    notification_date = (string)null,
                    plan_questionnaire = false,
                    _method = (string)null
                };

                var jsonPayload = JsonSerializer.Serialize(payload);
                
                Console.WriteLine($"Payload: {jsonPayload}");
                
                var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
                
                var url = $"https://{tenant}.mijndiad.nl/api/client-questionnaires";

                try
                {
                    // Update headers for this request
                    client.DefaultRequestHeaders.Remove("x-csrf-token");
                    client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
                    
                    var response = await client.PostAsync(url, content);
                    var result = await response.Content.ReadAsStringAsync();

                    Console.WriteLine($"Response: {result}");

                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"✓ Questionnaire {questionnaireId} sent successfully!");
                        successCount++;
                    }
                    else
                    {
                        Console.WriteLine($"✗ Failed to send questionnaire {questionnaireId}. Status: {response.StatusCode}");
                        failCount++;
                    }

                    // Small delay between requests to avoid rate limiting
                    if (i < questionnaireIds.Length - 1)
                    {
                        await Task.Delay(500); // 500ms delay
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error sending questionnaire {questionnaireId}: {ex.Message}");
                    failCount++;
                }
            }

            Console.WriteLine("\n=== Summary ===");
            Console.WriteLine($"✓ Successfully sent: {successCount} questionnaire(s)");
            if (failCount > 0)
            {
                Console.WriteLine($"✗ Failed: {failCount} questionnaire(s)");
            }
            Console.WriteLine($"Email: {clientEmail}");
        }
    }
}
