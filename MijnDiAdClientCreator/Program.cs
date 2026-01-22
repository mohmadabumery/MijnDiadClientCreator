using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("== Creating client ==");

        // Read required env vars (already working in your pipeline)
        var session = Environment.GetEnvironmentVariable("MIJNDIAD_SESSION");
        var xsrf = Environment.GetEnvironmentVariable("MIJNDIAD_XSRF");
        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");

        if (string.IsNullOrEmpty(session) || string.IsNullOrEmpty(xsrf))
        {
            Console.WriteLine("❌ Missing authentication environment variables.");
            return;
        }

        // Read JSON payload from CLI args
        string jsonPayload = "{}";
        if (args.Length >= 2 && args[0] == "--json")
        {
            jsonPayload = args[1];
        }

        using var client = new HttpClient();
        client.BaseAddress = new Uri($"https://{tenant}.mijndiad.nl/");

        // Required headers
        client.DefaultRequestHeaders.Add("Cookie", $"XSRF-TOKEN={xsrf}; mijndiad_session={session}");
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrf);
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

        var response = await client.PostAsync("api/clients", content);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine("❌ Client creation failed:");
            Console.WriteLine(responseBody);
            return;
        }

        using var doc = JsonDocument.Parse(responseBody);

        if (doc.RootElement.TryGetProperty("data", out var data) &&
            data.TryGetProperty("client", out var clientObj) &&
            clientObj.TryGetProperty("id", out var id))
        {
            Console.WriteLine($"✅ Client created successfully.");
            Console.WriteLine($"Client ID: {id.GetInt32()}");
        }
        else
        {
            Console.WriteLine("⚠️ Client created but ID not found.");
            Console.WriteLine(responseBody);
        }
    }
}
