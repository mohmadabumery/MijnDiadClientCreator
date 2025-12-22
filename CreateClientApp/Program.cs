using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

class CreateClientProgram
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("== MijnDiAd Client Creation ==");

        // Get inputs from workflow
        if (args.Length < 2 || args[0] != "--json")
        {
            Console.WriteLine("Usage: dotnet run -- --json '{...}'");
            Environment.Exit(1);
        }

        var dynamicsJson = args[1];
        var tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT");
        var sessionCookie = Environment.GetEnvironmentVariable("SESSION_COOKIE");
        var xsrfToken = Environment.GetEnvironmentVariable("XSRF_TOKEN");

        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
        {
            Console.WriteLine("❌ Missing session cookies from login workflow");
            Environment.Exit(1);
        }

        Console.WriteLine($"[1/2] Using authenticated session...");
        Console.WriteLine($"  Session: {sessionCookie.Substring(0, 20)}...");
        Console.WriteLine($"  XSRF: {xsrfToken.Substring(0, 20)}...");

        // Create HTTP client with cookies
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", xsrfToken);
        client.DefaultRequestHeaders.Add("Origin", $"https://{tenant}.mijndiad.nl");
        client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/clients/create");
        client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

        var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
        var url = $"https://{tenant}.mijndiad.nl/api/clients";

        Console.WriteLine($"[2/2] Creating client in MijnDiAd...");
        Console.WriteLine($"  Endpoint: {url}");

        try
        {
            var response = await client.PostAsync(url, content);
            var result = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"\n== Response Status: {(int)response.StatusCode} {response.StatusCode} ==");
            Console.WriteLine(result);

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("\n✅✅✅ SUCCESS! Client created in MijnDiAd EPD ✅✅✅");
            }
            else
            {
                Console.WriteLine($"\n❌ Failed to create client");
                Environment.Exit(1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Environment.Exit(1);
        }
    }
}
