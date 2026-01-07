using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        // Replace these with your login credentials
        string email = "your-email@example.com";
        string password = "your-password";

        using var client = new HttpClient();
        client.BaseAddress = new Uri("https://lngvty.mijndiad.nl/");

        Console.WriteLine("== Logging in ==");

        // 1️⃣ Login to get session and CSRF token
        var loginPayload = new
        {
            email = email,
            password = password
        };

        var loginContent = new StringContent(JsonSerializer.Serialize(loginPayload), Encoding.UTF8, "application/json");
        var loginResponse = await client.PostAsync("api/login", loginContent);
        var loginResult = await loginResponse.Content.ReadAsStringAsync();

        if (!loginResponse.IsSuccessStatusCode)
        {
            Console.WriteLine("Login failed: " + loginResult);
            return;
        }

        Console.WriteLine("Login successful.");

        // Extract cookies from response headers
        if (!loginResponse.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            Console.WriteLine("No session cookies received.");
            return;
        }

        string cookieHeader = string.Join("; ", cookies);
        client.DefaultRequestHeaders.Add("Cookie", cookieHeader);

        // You may need to extract XSRF-TOKEN from cookie manually if required
        string xsrfToken = ExtractXsrfToken(cookieHeader);
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", xsrfToken);

        // 2️⃣ Create client
        Console.WriteLine("== Creating client ==");
        string clientJson = args.Length > 0 ? args[0] : "{}"; // JSON payload from command line

        var clientContent = new StringContent(clientJson, Encoding.UTF8, "application/json");
        var createClientResponse = await client.PostAsync("api/clients", clientContent);
        string createClientResult = await createClientResponse.Content.ReadAsStringAsync();

        var createClientDoc = JsonDocument.Parse(createClientResult);
        if (createClientDoc.RootElement.TryGetProperty("data", out var dataElement) &&
            dataElement.TryGetProperty("client", out var clientElement) &&
            clientElement.TryGetProperty("id", out var idElement))
        {
            int clientId = idElement.GetInt32();
            Console.WriteLine($"Client created successfully. ID: {clientId}");

            // 3️⃣ Send questionnaires dynamically
            int[] questionnaireIds = new int[] { 4, 5 }; // Medical and Horizon

            foreach (var qid in questionnaireIds)
            {
                var questionnairePayload = new
                {
                    client_id = clientId,
                    questionnaire_ids = new int[] { qid },
                    send_to_client = 1,
                    email = clientElement.GetProperty("email").GetString(),
                    email_type = "EMAIL_TEMPLATE_INVITE_CLIENT_QUESTIONNAIRE"
                };

                var questionnaireContent = new StringContent(JsonSerializer.Serialize(questionnairePayload), Encoding.UTF8, "application/json");
                var questionnaireResponse = await client.PostAsync("api/client-questionnaires", questionnaireContent);
                string questionnaireResult = await questionnaireResponse.Content.ReadAsStringAsync();

                Console.WriteLine($"== Questionnaire {qid} Response ==");
                Console.WriteLine(questionnaireResult);
            }
        }
        else
        {
            Console.WriteLine("Client creation failed or response invalid:");
            Console.WriteLine(createClientResult);
        }

        Console.WriteLine("== Automation completed ==");
    }

    // Helper to extract XSRF-TOKEN from cookies
    static string ExtractXsrfToken(string cookieHeader)
    {
        foreach (var cookie in cookieHeader.Split(';'))
        {
            var parts = cookie.Split('=');
            if (parts.Length == 2 && parts[0].Trim() == "XSRF-TOKEN")
                return parts[1];
        }
        return "";
    }
}
