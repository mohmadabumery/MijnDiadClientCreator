using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    // Model matching your Dynamics onboarding form
    public class DynamicsClient
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
        public int GenderCode { get; set; }
        public string Address1_Country { get; set; }
        public string Nationality { get; set; }
    }

    static async Task Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: dotnet run --project Program.cs dynamics.json");
            return;
        }

        string jsonPath = args[0];
        if (!File.Exists(jsonPath))
        {
            Console.WriteLine($"File not found: {jsonPath}");
            return;
        }

        var dynamicsJson = await File.ReadAllTextAsync(jsonPath);
        var clientData = JsonSerializer.Deserialize<DynamicsClient>(dynamicsJson);

        if (clientData == null)
        {
            Console.WriteLine("Failed to parse Dynamics JSON.");
            return;
        }

        // Build payload for MijnDiAd API
        var mijnDiadPayload = new
        {
            firstname = clientData.FirstName,
            lastname = clientData.LastName,
            gender = clientData.GenderCode,
            nationality = clientData.Nationality ?? "",
            date_of_birth = clientData.BirthDate,
            date_of_intake = DateTime.UtcNow.ToString("yyyy-MM-dd"), // today
            email = clientData.EMailAddress1,
            phonenumber = clientData.Address1_Telephone1,
            reminder = 1,
            confirmation = 1,
            invoice_relation_id = 15,  // default value
            invoice_send_method = 1,
            is_active = 1,
            address = new
            {
                country = clientData.Address1_Country,
                zipcode = clientData.Address1_PostalCode,
                house_number = clientData.Address1_PostOfficeBox,
                street = clientData.Address1_Line1,
                city = clientData.Address1_City
            },
            invoice_address = new { country = clientData.Address1_Country },
            different_post_address = 0,
            client_attributes = new object[] { },
            client_group_ids = (object)null,
            allow_dubble_email = 0
        };

        // Read secrets from environment variables (GitHub Actions)
        string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";
        string sessionCookie = Environment.GetEnvironmentVariable("MIJNDIAD_SESSION") ?? "";
        string xsrfToken = Environment.GetEnvironmentVariable("MIJNDIAD_XSRF") ?? "";

        if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
        {
            Console.WriteLine("Session cookie or CSRF token missing in environment variables.");
            return;
        }

        var jsonPayload = JsonSerializer.Serialize(mijnDiadPayload, new JsonSerializerOptions { WriteIndented = true });
        var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

        using var client = new HttpClient();
        client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
        client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

        var response = await client.PostAsync($"https://{tenant}.mijndiad.nl/api/clients", content);
        var responseBody = await response.Content.ReadAsStringAsync();

        Console.WriteLine("== MijnDiAd Response ==");
        Console.WriteLine(responseBody);
    }
}
