using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length < 2 || args[0] != "--json")
            {
                Console.WriteLine("Usage: dotnet run -- --json '{\"firstname\":\"John\", ...}'");
                return;
            }

            string clientJson = args[1];

            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") 
                            ?? throw new Exception("MIJNDIAD_TENANT not set");
            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME") 
                            ?? throw new Exception("MIJNDIAD_USERNAME not set");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD") 
                            ?? throw new Exception("MIJNDIAD_PASSWORD not set");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET") 
                            ?? throw new Exception("MIJNDIAD_TOTP_SECRET not set");

            Console.WriteLine("== MijnDiAd Laravel Automation ==");

            int maxRetries = 3;
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                Console.WriteLine($"--- Attempt {attempt} ---");
                try
                {
                    using var handler = new HttpClientHandler { CookieContainer = new CookieContainer() };
                    using var client = new HttpClient(handler);
                    client.Timeout = TimeSpan.FromSeconds(30);

                    // 1️⃣ Get CSRF cookie
                    await GetSanctumCsrf(client, tenant);

                    // 2️⃣ Login
                    await Login(client, tenant, username, password, totpSecret);

                    // 3️⃣ Visit dashboard to refresh CSRF token
                    string xsrfToken = await GetDashboardCsrf(client, tenant);

                    // 4️⃣ Create client
                    bool created = await CreateClient(client, tenant, clientJson, xsrfToken);

                    if (created)
                    {
                        Console.WriteLine("\n✅✅✅ SUCCESS! Client created ✅✅✅");
                        return;
                    }
                    else
                    {
                        Console.WriteLine("⚠ CSRF/session expired — retrying...");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Attempt {attempt} failed: {ex.Message}");
                }

                await Task.Delay(2000); // short wait before retry
            }

            Console.WriteLine("\n❌ All attempts failed.");
            Environment.Exit(1);
        }

        static async Task GetSanctumCsrf(HttpClient client, string tenant)
        {
            Console.WriteLine("[1/4] Bootstrapping Sanctum...");
            var response = await client.GetAsync($"https://{tenant}.mijndiad.nl/sanctum/csrf-cookie");
            response.EnsureSuccessStatusCode();
            Console.WriteLine("✓ CSRF cookie fetched");
        }

        static async Task Login(HttpClient client, string tenant, string email, string password, string totpSecret)
        {
            Console.WriteLine("[2/4] Logging in...");

            var form = new Dictionary<string, string>
            {
                ["email"] = email,
                ["password"] = password,
                ["totp_code"] = GenerateTotp(totpSecret)
            };

            var content = new FormUrlEncodedContent(form);

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml");
            client.DefaultRequestHeaders.Add("Referer", $"https://{tenant}.mijndiad.nl/login");

            var response = await client.PostAsync($"https://{tenant}.mijndiad.nl/login", content);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                throw new Exception($"Login failed: {(int)response.StatusCode} {body}");
            }

            Console.WriteLine("✓ Login successful");
        }

        static async Task<string> GetDashboardCsrf(HttpClient client, string tenant)
        {
            Console.WriteLine("[3/4] Visiting dashboard...");

            var response = await client.GetAsync($"https://{tenant}.mijndiad.nl/dashboard");
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();

            var match = Regex.Match(html, "<meta name=\"csrf-token\" content=\"([^\"]+)\"");
            if (!match.Success) throw new Exception("Dashboard CSRF token not found");

            string token = match.Groups[1].Value;
            Console.WriteLine("✓ CSRF refreshed from dashboard");
            return token;
        }

        static async Task<bool> CreateClient(HttpClient client, string tenant, string json, string xsrfToken)
        {
            Console.WriteLine("[4/4] Creating client...");

            var request = new HttpRequestMessage(HttpMethod.Post, $"https://{tenant}.mijndiad.nl/api/clients");
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            request.Headers.Add("X-CSRF-TOKEN", xsrfToken);
            request.Headers.Add("X-Requested-With", "XMLHttpRequest");
            request.Headers.Add("Accept", "application/json, text/plain, */*");
            request.Headers.Add("Referer", $"https://{tenant}.mijndiad.nl/clients/create");

            var response = await client.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"\n== STATUS {(int)response.StatusCode} ==");
            Console.WriteLine(body);

            return response.IsSuccessStatusCode;
        }

        static string GenerateTotp(string base32Secret)
        {
            if (string.IsNullOrEmpty(base32Secret)) return "000000";

            var key = Base32Decode(base32Secret);
            var timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
            var data = BitConverter.GetBytes(timestep);
            if (BitConverter.IsLittleEndian) Array.Reverse(data);

            using var hmac = new System.Security.Cryptography.HMACSHA1(key);
            var hash = hmac.ComputeHash(data);

            int offset = hash[^1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            return (binary % 1_000_000).ToString("D6");
        }

        static byte[] Base32Decode(string input)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var output = new byte[input.Length * 5 / 8];
            int bitBuffer = 0, bitCount = 0, index = 0;

            foreach (char c in input.TrimEnd('='))
            {
                int charIndex = alphabet.IndexOf(c);
                if (charIndex < 0) continue;

                bitBuffer = (bitBuffer << 5) | charIndex;
                bitCount += 5;

                if (bitCount >= 8)
                {
                    output[index++] = (byte)(bitBuffer >> (bitCount - 8));
                    bitCount -= 8;
                }
            }

            Array.Resize(ref output, index);
            return output;
        }
    }
}
