using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("== CreateClient ==");

        var tenant = Env("MIJNDIAD_TENANT");
        var clientJson = await File.ReadAllTextAsync("pending/client.json");
        var cookies = JsonSerializer.Deserialize<List<Cookie>>(
            await File.ReadAllTextAsync("session/session.json")
        )!;

        var handler = new HttpClientHandler { UseCookies = false };
        using var client = new HttpClient(handler);

        var cookieHeader = string.Join("; ",
            cookies.Select(c => $"{c.Name}={c.Value}")
        );

        client.DefaultRequestHeaders.Add("Cookie", cookieHeader);
        client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
        client.DefaultRequestHeaders.Add("x-csrf-token",
            cookies.First(c => c.Name == "XSRF-TOKEN").Value);

        var res = await client.PostAsync(
            $"https://{tenant}.mijndiad.nl/api/clients",
            new StringContent(clientJson, Encoding.UTF8, "application/json")
        );

        var body = await res.Content.ReadAsStringAsync();
        Console.WriteLine(body);

        res.EnsureSuccessStatusCode();
        Console.WriteLine("✅ Client created");
    }

    static string Env(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new Exception($"Missing env var {name}");

    record Cookie(string Name, string Value);
}
