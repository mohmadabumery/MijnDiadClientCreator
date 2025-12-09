using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Playwright;

class Program
{
    public class ClientData
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string EMailAddress1 { get; set; }
        public string Address1_Telephone1 { get; set; }
        public string BirthDate { get; set; }
        public string Address1_Line1 { get; set; }
        public string Address1_City { get; set; }
        public string Address1_PostalCode { get; set; }
        public string Address1_PostOfficeBox { get; set; }
        public string GenderCode { get; set; } // 1=male, 2=female
        public string Address1_Country { get; set; }
    }

    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Please provide the path to the Dynamics JSON file as argument.");
            return;
        }

        string jsonPath = args[0];
        if (!File.Exists(jsonPath))
        {
            Console.WriteLine($"File not found: {jsonPath}");
            return;
        }

        var json = await File.ReadAllTextAsync(jsonPath);
        var client = JsonSerializer.Deserialize<ClientData>(json);

        if (client == null)
        {
            Console.WriteLine("Failed to parse JSON.");
            return;
        }

        string tenant = "lngvty"; // Your tenant
        var (session, xsrf) = await FetchCookiesWithPlaywright(tenant);

        using var handler = new HttpClientHandler { UseCookies = false };
        using var http = new HttpClient(handler);

        var payload = new
        {
            firstname = client.FirstName,
            lastname = client.LastName,
            gender = int.Parse(client.GenderCode),
            nationality = client.Address1_Country,
            date_of_birth = client.BirthDate,
            date_of_intake = DateTime.UtcNow.ToString("yyyy-MM-dd"),
            email = client.EMailAddress1,
            phonenumber = client.Address1_Telephone1,
            reminder = 1,
            confirmation = 1,
            invoice_relation_id = 15,
            invoice_send_method = 1,
            is_active = 1,
            address = new
            {
                country = client.Address1_Country,
                zipcode = client.Address1_PostalCode,
                house_number = client.Address1_PostOfficeBox,
                street = client.Address1_Line1,
                city = client.Address1_City
            },
            invoice_address = new
            {
                country = client.Address1_Country
            },
            different_post_address = 0,
            client_attributes = Array.Empty<object>(),
            client_group_ids = (object)null,
            allow_dubble_email = 0
        };

        var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        http.DefaultRequestHeaders.Add("x-csrf-token", xsrf);
        http.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={session}; XSRF-TOKEN={xsrf}");

        var response = await http.PostAsync($"https://{tenant}.mijndiad.nl/api/clients", content);
        var responseBody = await response.Content.ReadAsStringAsync();

        Console.WriteLine("== Response ==");
        Console.WriteLine(responseBody);
    }

    static async Task<(string session, string xsrf)> FetchCookiesWithPlaywright(string tenant)
    {
        using var playwright = await Playwright.CreateAsync();
        var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
        var context = await browser.NewContextAsync();
        var page = await context.NewPageAsync();

        string email = Environment.GetEnvironmentVariable("MIJNDIAD_EMAIL");
        string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");

        await page.GotoAsync($"https://{tenant}.mijndiad.nl/login");
        await page.FillAsync("input[name='email']", email);
        await page.FillAsync("input[name='password']", password);
        await page.ClickAsync("button[type='submit']");
        await page.WaitForNavigationAsync();

        var cookies = await context.CookiesAsync();
        var session = cookies.First(c => c.Name == $"{tenant}_session").Value;
        var xsrf = cookies.First(c => c.Name == "XSRF-TOKEN").Value;

        await browser.CloseAsync();
        return (session, xsrf);
    }
}
