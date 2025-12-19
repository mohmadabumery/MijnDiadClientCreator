using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Linq;

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

            // Step 1: Get initial session cookies from login page
            Console.WriteLine("\n[1/4] Fetching initial session cookies...");
            var (initialSessionCookie, initialXsrfToken) = await GetInitialSessionCookies(tenant);

            if (string.IsNullOrEmpty(initialSessionCookie) || string.IsNullOrEmpty(initialXsrfToken))
            {
                Console.WriteLine("❌ Failed to get initial cookies from login page.");
                return;
            }

            // Step 2: Login and get authenticated session cookies
            Console.WriteLine("\n[2/4] Logging in to MijnDiAd...");
            var (sessionCookie, xsrfToken) = await LoginToMijnDiad(username, password, totpSecret, tenant, initialSessionCookie, initialXsrfToken);

            if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            {
                Console.WriteLine("❌ Login failed. Could not retrieve session cookies.");
                return;
            }

            Console.WriteLine("✓ Login successful!");

            // Step 3: Post client data to MijnDiAd API
            Console.WriteLine("\n[3/4] Creating client in MijnDiAd...");
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

            var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var url = $"https://{tenant}.mijndiad.nl/api/clients";

            try
            {
                var response = await client.PostAsync(url, content);
                var result = await response.Content.ReadAsStringAsync();

                Console.WriteLine("\n[4/4] MijnDiAd Response:");
                Console.WriteLine(result);

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("\n✓ Client created successfully!");

                    // Clean up processed file
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

        // New method: GET login page to retrieve initial cookies
        static async Task<(string sessionCookie, string xsrfToken)> GetInitialSessionCookies(string tenant)
        {
            using var client = new HttpClient();
            var response = await client.GetAsync($"https://{tenant}.mijndiad.nl/login");

            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                string sessionCookie = null;
                string xsrfToken = null;

                foreach (var cookie in cookies)
                {
                    if (cookie.Contains($"{tenant}_session="))
                        sessionCookie = ExtractCookieValue(cookie, $"{tenant}_session=");
                    if (cookie.Contains("XSRF-TOKEN="))
                        xsrfToken = ExtractCookieValue(cookie, "XSRF-TOKEN=");
                }

                return (sessionCookie, xsrfToken);
            }

            return (null, null);
        }

        static async Task<(string sessionCookie, string xsrfToken)> LoginToMijnDiad(
            string username,
            string password,
            string totpSecret,
            string tenant,
            string initialSessionCookie,
            string initialXsrfToken)
        {
            using var client = new HttpClient();

            // Generate TOTP code
            string totpCode = GenerateTOTP(totpSecret);
            Console.WriteLine($"Generated TOTP: {totpCode}");

            var loginData = new
            {
                email = username,
                password = password,
                totp_code = totpCode,
                tenant = tenant
            };

            var loginJson = JsonSerializer.Serialize(loginData);
            var content = new StringContent(loginJson, Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage(HttpMethod.Post, $"https://{tenant}.mijndiad.nl/login");
            request.Content = content;
            request.Headers.Add("Cookie", $"{tenant}_session={initialSessionCookie}; XSRF-TOKEN={initialXsrfToken}");

            try
            {
                var response = await client.SendAsync(request);

                if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
                {
                    string sessionCookie = null;
                    string xsrfToken = null;

                    foreach (var cookie in cookies)
                    {
                        if (cookie.Contains($"{tenant}_session="))
                            sessionCookie = ExtractCookieValue(cookie, $"{tenant}_session=");
                        if (cookie.Contains("XSRF-TOKEN="))
                            xsrfToken = ExtractCookieValue(cookie, "XSRF-TOKEN=");
                    }

                    return (sessionCookie, xsrfToken);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Login error: {ex.Message}");
            }

            return (null, null);
        }

        static string ExtractCookieValue(string cookieHeader, string cookieName)
        {
            int start = cookieHeader.IndexOf(cookieName);
            if (start == -1) return null;

            start += cookieName.Length;
            int end = cookieHeader.IndexOf(';', start);
            if (end == -1) end = cookieHeader.Length;

            return cookieHeader.Substring(start, end - start);
        }

        static string GenerateTOTP(string base32Secret, int digits = 6, int period = 30)
        {
            byte[] secretBytes = Base32Decode(base32Secret);

            long epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long counter = epoch / period;

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
            for (int i = 0; i < bits.Length; i += 8)
            {
                int length = Math.Min(8, bits.Length - i);
                string segment = bits.Substring(i, length);
                if (segment.Length == 8)
                {
                    bytes.Add(Convert.ToByte(segment, 2));
                }
            }

            return bytes.ToArray();
        }
    }
}
