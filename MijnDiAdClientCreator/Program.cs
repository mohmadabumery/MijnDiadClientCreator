using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.WriteLine("=== MijnDiAd Client Creator ===");

        string jsonPath = GetArg(args, "--json-file");
        if (string.IsNullOrEmpty(jsonPath) || !File.Exists(jsonPath))
        {
            Console.WriteLine("❌ Missing or invalid --json-file");
            return 1;
        }

        string clientJson = File.ReadAllText(jsonPath);
        Console.WriteLine($"Read JSON from {jsonPath} ({clientJson.Length} chars)");

        using var doc = JsonDocument.Parse(clientJson);
        Console.WriteLine("✓ JSON is valid");

        string tenant = Env("MIJNDIAD_TENANT");
        string username = Env("MIJNDIAD_USERNAME");
        string password = Env("MIJNDIAD_PASSWORD");
        string totpSecret = Env("MIJNDIAD_TOTP_SECRET");

        string baseUrl = $"https://{tenant}.mijndiad.nl";
        Console.WriteLine($"Target: {baseUrl}");

        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookies,
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.All
        };

        using var client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");

        /* ---------------------------------------------------------
         * 1. LOGIN
         * ---------------------------------------------------------*/
        Console.WriteLine("[1/6] Logging in...");
        await Login(client, baseUrl, username, password, totpSecret);
        Console.WriteLine("✓ Login successful");

        /* ---------------------------------------------------------
         * 2. SANCTUM INIT
         * ---------------------------------------------------------*/
        Console.WriteLine("[2/6] Initializing Sanctum...");
        await client.GetAsync($"{baseUrl}/sanctum/csrf-cookie");

        /* ---------------------------------------------------------
         * 3. LOAD CREATE FORM (GET REAL CSRF)
         * ---------------------------------------------------------*/
        Console.WriteLine("[3/6] Loading create form...");
        var createPage = await client.GetStringAsync($"{baseUrl}/clients/create");
        string csrfToken = ExtractCsrf(createPage);
        if (string.IsNullOrEmpty(csrfToken))
            throw new Exception("Failed to extract CSRF token");

        Console.WriteLine($"✓ Fresh CSRF token ({csrfToken.Length} chars)");

        /* ---------------------------------------------------------
         * 4. BIND API SESSION
         * ---------------------------------------------------------*/
        Console.WriteLine("[4/6] Binding API session...");
        var userResp = await client.GetAsync($"{baseUrl}/api/user");
        if (!userResp.IsSuccessStatusCode)
            throw new Exception("API session binding failed");

        Console.WriteLine("✓ API session bound");

        /* ---------------------------------------------------------
         * 5. BUILD PAYLOAD (IMPORTANT FIX)
         * ---------------------------------------------------------*/
        Console.WriteLine("[5/6] Preparing payload...");
        var formFields = BuildForm(clientJson, csrfToken);

        var content = new FormUrlEncodedContent(formFields);

        /* ---------------------------------------------------------
         * 6. CREATE CLIENT
         * ---------------------------------------------------------*/
        Console.WriteLine("[6/6] Creating client...");
        var resp = await client.PostAsync($"{baseUrl}/api/clients", content);

        Console.WriteLine($"Status: {resp.StatusCode}");
        string body = await resp.Content.ReadAsStringAsync();
        Console.WriteLine(body);

        if (!resp.IsSuccessStatusCode)
        {
            Console.WriteLine("❌ Client creation failed");
            return 1;
        }

        Console.WriteLine("✅ Client successfully created");
        return 0;
    }

    /* ============================================================
     * HELPERS
     * ============================================================*/

    static async Task Login(HttpClient client, string baseUrl, string user, string pass, string totpSecret)
    {
        string loginPage = await client.GetStringAsync($"{baseUrl}/login");
        string csrf = ExtractCsrf(loginPage);

        var data = new Dictionary<string, string>
        {
            ["_token"] = csrf,
            ["email"] = user,
            ["password"] = pass,
            ["totp"] = GenerateTotp(totpSecret)
        };

        var resp = await client.PostAsync($"{baseUrl}/login", new FormUrlEncodedContent(data));
        if (!resp.IsSuccessStatusCode)
            throw new Exception("Login failed");
    }

    static Dictionary<string, string> BuildForm(string json, string csrfToken)
    {
        var dict = new Dictionary<string, string>
        {
            // 🔑 REQUIRED HIDDEN FIELDS (THE FIX)
            ["_token"] = csrfToken,
            ["_method"] = "POST",
            ["submit_type"] = "save",
            ["wizard_step"] = "final"
        };

        using var doc = JsonDocument.Parse(json);
        FlattenJson("", doc.RootElement, dict);
        return dict;
    }

    static void FlattenJson(string prefix, JsonElement el, Dictionary<string, string> dict)
    {
        if (el.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in el.EnumerateObject())
                FlattenJson($"{prefix}{p.Name}.", p.Value, dict);
        }
        else if (el.ValueKind == JsonValueKind.Array)
        {
            int i = 0;
            foreach (var v in el.EnumerateArray())
                FlattenJson($"{prefix}{i++}.", v, dict);
        }
        else
        {
            dict[prefix.TrimEnd('.')] = el.ToString();
        }
    }

    static string ExtractCsrf(string html)
    {
        var m = Regex.Match(html, "name=\"_token\" value=\"([^\"]+)\"");
        return m.Success ? m.Groups[1].Value : "";
    }

    static string GenerateTotp(string secret)
    {
        var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(secret));
        return totp.ComputeTotp();
    }

    static string Env(string name)
    {
        var v = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrEmpty(v))
            throw new Exception($"Missing env var: {name}");
        return v;
    }

    static string GetArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i] == name)
                return args[i + 1];
        return null;
    }
}
