using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace MijnDiAdClientCreator
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // JSON input from arguments
            string clientJson = args.Length > 0 ? args[0] : "{}";

            using var client = new HttpClient();
            client.BaseAddress = new Uri("https://lngvty.mijndiad.nl/api/");
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // TODO: Set your auth cookies or headers here
            client.DefaultRequestHeaders.Add("Cookie", "lngvty_session=YOUR_SESSION; XSRF-TOKEN=YOUR_XSRF_TOKEN");
            client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", "YOUR_XSRF_TOKEN");

            try
            {
                // 1️⃣ Create client
                Console.WriteLine("== Creating client ==");
                var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
                var createResponse = await client.PostAsync("clients", clientContent);
                string createResult = await createResponse.Content.ReadAsStringAsync();
                Console.WriteLine("== Client Response ==");
                Console.WriteLine(createResult);

                // Parse client_id from response
                using var doc = JsonDocument.Parse(createResult);
                int clientId = doc.RootElement.GetProperty("data").GetProperty("client").GetProperty("id").GetInt32();
                string clientEmail = doc.RootElement.GetProperty("data").GetProperty("client").GetProperty("email").GetString();

                Console.WriteLine($"Client ID: {clientId}");
                Console.WriteLine($"Client Email: {clientEmail}");

                // 2️⃣ Send questionnaires dynamically
                Console.WriteLine("== Sending questionnaires ==");

                var questionnairePayload = new
                {
                    client_id = clientId,
                    questionnaire_ids = new int[] { 4, 5 }, // Medical + Horizon
                    send_to_client = 1,
                    email = clientEmail,
                    email_data = new
                    {
                        use_custom = false,
                        concept_id = (int?)null,
                        subject = "",
                        content = "",
                        ics = "0",
                        questionnaire_ids = new int[] { }
                    },
                    attachments = Array.Empty<object>(),
                    client_agreements = Array.Empty<object>(),
                    client_documents = Array.Empty<object>(),
                    client_files = Array.Empty<object>(),
                    concept_attachments = Array.Empty<object>(),
                    concept_id = (int?)null,
                    content = "",
                    documents = Array.Empty<object>(),
                    email_template_id = (int?)null,
                    email_type = "EMAIL_TEMPLATE_INVITE_CLIENT_QUESTIONNAIRE",
                    general_files = Array.Empty<object>(),
                    ics = "0",
                    _method = (string?)null
                };

                string questionnaireJson = JsonSerializer.Serialize(questionnairePayload);
                var questionnaireContent = new StringContent(questionnaireJson, Encoding.UTF8, "application/json");
                var questionnaireResponse = await client.PostAsync("client-questionnaires", questionnaireContent);
                string questionnaireResult = await questionnaireResponse.Content.ReadAsStringAsync();

                Console.WriteLine("== Questionnaires Response ==");
                Console.WriteLine(questionnaireResult);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
