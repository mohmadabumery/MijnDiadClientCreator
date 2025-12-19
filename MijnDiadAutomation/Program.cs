using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("== Dynamics → MijnDiAd Automation with Auto-Login ==");

            if (args.Length == 0)
            {
                Console.WriteLine("Please provide the path to the Dynamics JSON file as an argument.");
                return;
            }

            string jsonFilePath = args[0];
            if (!File.Exists(jsonFilePath))
            {
                Console.WriteLine($"File not found: {jsonFilePath}");
                return;
            }

            string dynamicsJson = await File.ReadAllTextAsync(jsonFilePath);

            // Read secrets from environment
            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(totpSecret))
            {
                Console.WriteLine("Missing credentials. Set MIJNDIAD_USERNAME, MIJNDIAD_PASSWORD, and MIJNDIAD_TOTP_SECRET as GitHub secrets.");
                return;
            }

            // Setup HttpClient with CookieContainer to handle cookies automatically
            var cookieContainer = new CookieContainer();
            var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true,
                AllowAutoRedirect = true
            };

            using var client = new HttpClient(handler);
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

            // Step 1: GET /login to get initial session cookies
            Console.WriteLine("\n[1/5] Fetching initial session cookies...");
            var getResponse = await client.GetAsync($"https://{tenant}.mijndiad.nl/login");
            getResponse.EnsureSuccessStatusCode();

            // Extract cookies
            var cookies = cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl/"));
            string initialSessionCookie = cookies[$"{tenant}_session"]?.Value;
            string initialXsrfToken = cookies["XSRF-TOKEN"]?.Value;

            if (string.IsNullOrEmpty(initialSessionCookie) || string.IsNullOrEmpty(initialXsrfToken))
            {
                Console.WriteLine("❌ Failed to get initial cookies.");
                return;
            }

            Console.WriteLine($"Initial session: {initialSessionCookie}");
            Console.WriteLine($"Initial XSRF: {initialXsrfToken}");

            // Step 2: Generate TOTP
            string totpCode = GenerateTOTP(totpSecret);
            Console.WriteLine($"\n[2/5] Generated TOTP: {totpCode}");

            // Step 3: POST /login with credentials + cookies + TOTP
            Console.WriteLine("\n[3/5] Logging in to MijnDiAd...");
            var loginData = new
            {
                email = username,
                password = password,
                totp_code = totpCode,
                tenant = tenant
            };
            var loginJson = JsonSerializer.Serialize(loginData);
            var loginContent = new StringContent(loginJson, Encoding.UTF8, "application/json");

            var loginRequest = new HttpRequestMessage(HttpMethod.Post, $"https://{tenant}.mijndiad.nl/login");
            loginRequest.Content = loginContent;
            loginRequest.Headers.Add("Referer", $"https://{tenant}.mijndiad.nl/login");
            loginRequest.Headers.Add("Accept", "application/json");

            var loginResponse = await client.SendAsync(loginRequest);
            if (!loginResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Login POST failed: {loginResponse.StatusCode}");
                return;
            }

            // Step 4: Extract authenticated session cookies
            cookies = cookieContainer.GetCookies(new Uri($"https://{tenant}.mijndiad.nl/"));
            string sessionCookie = cookies[$"{tenant}_session"]?.Value;
            string xsrfToken = cookies["XSRF-TOKEN"]?.Value;

            if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            {
                Console.WriteLine("❌ Login failed. Could not retrieve authenticated session cookies.");
                return;
            }

            Console.WriteLine("✓ Login successful!");

            // Step 5: Post Dynamics JSON to MijnDiAd API
            Console.WriteLine("\n[4/5] Sending Dynamics JSON to MijnDiAd API...");
            client.DefaultRequestHeaders.Remove("User-Agent");
            client.DefaultRequestHeaders.Remove("Accept");
            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);

            var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var apiUrl = $"https://{tenant}.mijndiad.nl/api/clients";

            try
            {
                var response = await client.PostAsync(apiUrl, content);
                var result = await response.Content.ReadAsStringAsync();

                Console.WriteLine("\n[5/5] MijnDiAd Response:");
                Console.WriteLine(result);

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("\n✓ Client created successfully!");
                    File.Delete(jsonFilePath);
                    Console.WriteLine($"✓ Cleaned up: {jsonFilePath}");
                }
                else
                {
                    Console.WriteLine($"\n❌ Failed to create client. Status: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error sending request: {ex.Message}");
            }
        }

        static string GenerateTOTP(string base32Secret, int digits = 6, int period = 30)
        {
            byte[] secretBytes = Base32Decode(base32Secret);
            long counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / period;

            byte[] counterBytes = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                counterBytes[i] = (byte)(counter & 0xFF);
                counter >>= 8;
            }

            using var hmac = new HMACSHA1(secretBytes);
            byte[] hash = hmac.ComputeHash(counterBytes);

            int offset = hash[hash.Length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) |
                        ((hash[offset + 1] & 0xFF) << 16) |
                        ((hash[offset + 2] & 0xFF) << 8) |
                        (hash[offset + 3] & 0xFF);

            int otp = binary % (int)Math.Pow(10, digits);
            return otp.ToString($"D{digits}");
        }

        static byte[] Base32Decode(string base32)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            string bits = "";

            foreach (char c in base32.ToUpper())
            {
                int index = alphabet.IndexOf(c);
                if (index < 0) continue;
                bits += Convert.ToString(index, 2).PadLeft(5, '0');
            }

            var bytes = new System.Collections.Generic.List<byte>();
            for (int i = 0; i + 8 <= bits.Length; i += 8)
            {
                bytes.Add(Convert.ToByte(bits.Substring(i, 8), 2));
            }

            return bytes.ToArray();
        }
    }
}
