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
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

            // Parse input JSON
            string dynamicsJson = null;
            if (args.Length == 2 && args[0] == "--json")
            {
                dynamicsJson = args[1];
            }
            else if (args.Length == 1 && File.Exists(args[0]))
            {
                dynamicsJson = await File.ReadAllTextAsync(args[0]);
            }
            else
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("dotnet run -- --json \"{ ... }\"");
                Console.WriteLine("or");
                Console.WriteLine("dotnet run path/to/file.json");
                return;
            }

            // Read credentials from environment
            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("❌ Missing credentials. Set MIJNDIAD_USERNAME and MIJNDIAD_PASSWORD as GitHub secrets.");
                return;
            }

            // Step 1: Login to get fresh session cookies
            Console.WriteLine("\n[Step 1/3] Logging in to MijnDiAd...");
            var (sessionCookie, xsrfToken) = await LoginToMijnDiad(username, password, totpSecret, tenant);

            if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            {
                Console.WriteLine("❌ Login failed. Could not retrieve session cookies.");
                return;
            }

            Console.WriteLine("✓ Login successful! Got fresh session cookies.");

            // Step 2: Post client data to MijnDiAd API
            Console.WriteLine("\n[Step 2/3] Creating client in MijnDiAd...");
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-csrf-token", xsrfToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{tenant}_session={sessionCookie}; XSRF-TOKEN={xsrfToken}");

            var content = new StringContent(dynamicsJson, Encoding.UTF8, "application/json");
            var url = $"https://{tenant}.mijndiad.nl/api/clients";

            try
            {
                var response = await client.PostAsync(url, content);
                var result = await response.Content.ReadAsStringAsync();

                Console.WriteLine("\n[Step 3/3] MijnDiAd API Response:");
                Console.WriteLine(result);

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("\n✓✓✓ SUCCESS! Client created in MijnDiAd EPD ✓✓✓");
                }
                else
                {
                    Console.WriteLine($"\n❌ Failed to create client. Status: {response.StatusCode}");
                    Environment.Exit(1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error sending request: {ex.Message}");
                Environment.Exit(1);
            }
        }

        // -------------------- LOGIN FUNCTION --------------------
        static async Task<(string sessionCookie, string xsrfToken)> LoginToMijnDiad(string username, string password, string totpSecret, string tenant)
        {
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true, // follow redirects
                UseCookies = false        // manually handle cookies
            };
            using var client = new HttpClient(handler);

            // Generate TOTP if secret provided
            string totpCode = null;
            if (!string.IsNullOrWhiteSpace(totpSecret))
            {
                totpCode = GenerateTOTP(totpSecret);
                Console.WriteLine($"  Generated TOTP code: {totpCode}");
            }

            // Fetch login page to get XSRF token
            var loginPageUrl = $"https://{tenant}.mijndiad.nl/login";
            Console.WriteLine($"  Fetching login page for tenant '{tenant}' ...");
            var pageResponse = await client.GetAsync(loginPageUrl);
            pageResponse.EnsureSuccessStatusCode();

            string xsrfToken = null;
            if (pageResponse.Headers.TryGetValues("Set-Cookie", out var pageCookies))
            {
                foreach (var cookie in pageCookies)
                {
                    if (cookie.Contains("XSRF-TOKEN="))
                    {
                        xsrfToken = ExtractCookieValue(cookie, "XSRF-TOKEN=");
                        Console.WriteLine($"  ✓ Extracted XSRF token from cookie");
                    }
                }
            }

            if (xsrfToken == null)
            {
                Console.WriteLine("❌ Could not find XSRF token.");
                return (null, null);
            }

            // Prepare login payload
            var loginData = new
            {
                email = username,
                password = password,
                totp = totpCode,
                remember = true
            };
            var loginJson = JsonSerializer.Serialize(loginData);
            var content = new StringContent(loginJson, Encoding.UTF8, "application/json");

            // Post to AJAX login endpoint
            var loginUrl = $"https://{tenant}.mijndiad.nl/api/auth/login";
            var request = new HttpRequestMessage(HttpMethod.Post, loginUrl)
            {
                Content = content
            };
            request.Headers.Add("X-XSRF-TOKEN", xsrfToken);

            Console.WriteLine("  Sending login request...");
            var response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Login request failed with status {response.StatusCode}");
                return (null, null);
            }

            // Extract session cookie
            string sessionCookie = null;
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    if (cookie.Contains($"{tenant}_session="))
                    {
                        sessionCookie = ExtractCookieValue(cookie, $"{tenant}_session=");
                        Console.WriteLine($"  ✓ Got session cookie");
                    }
                }
            }

            if (sessionCookie == null)
            {
                Console.WriteLine("❌ Could not find session cookie.");
                return (null, null);
            }

            return (sessionCookie, xsrfToken);
        }

        // -------------------- HELPER FUNCTIONS --------------------
        static string ExtractCookieValue(string cookieHeader, string cookieName)
        {
            int start = cookieHeader.IndexOf(cookieName);
            if (start == -1) return null;
            start += cookieName.Length;
            int end = cookieHeader.IndexOf(';', start);
            if (end == -1) end = cookieHeader.Length;
            return cookieHeader.Substring(start, end - start).Trim();
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
