using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

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
                Console.WriteLine("Usage: dotnet run -- --json \"{ ... }\" or dotnet run path/to/file.json");
                return;
            }

            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("❌ Missing credentials. Set MIJNDIAD_USERNAME and MIJNDIAD_PASSWORD as GitHub secrets.");
                return;
            }

            Console.WriteLine("\n[Step 1/3] Logging in to MijnDiAd...");
            var (sessionCookie, xsrfToken) = await LoginToMijnDiad(username, password, totpSecret, tenant);

            if (string.IsNullOrEmpty(sessionCookie) || string.IsNullOrEmpty(xsrfToken))
            {
                Console.WriteLine("❌ Login failed. Could not retrieve session cookies.");
                return;
            }

            Console.WriteLine("✓ Login successful! Got fresh session cookies.");

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

        static async Task<(string sessionCookie, string xsrfToken)> LoginToMijnDiad(string username, string password, string totpSecret, string tenant)
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true };
            using var client = new HttpClient(handler);

            // Generate TOTP code
            string totpCode = string.IsNullOrWhiteSpace(totpSecret) ? null : GenerateTOTP(totpSecret);
            if (!string.IsNullOrWhiteSpace(totpCode))
                Console.WriteLine($"  Generated TOTP code: {totpCode}");

            // Step 1: Get login page to extract XSRF-TOKEN
            var loginPageUrl = $"https://{tenant}.mijndiad.nl/login";
            var pageResponse = await client.GetAsync(loginPageUrl);
            string xsrfFromPage = null;
            if (pageResponse.Headers.TryGetValues("Set-Cookie", out var pageCookies))
            {
                foreach (var cookie in pageCookies)
                {
                    if (cookie.Contains("XSRF-TOKEN="))
                        xsrfFromPage = ExtractCookieValue(cookie, "XSRF-TOKEN=");
                }
            }

            // Step 2: Send form-encoded login POST
            var postData = new Dictionary<string, string>
            {
                ["email"] = username,
                ["password"] = password,
                ["totp"] = totpCode ?? "",
                ["remember"] = "true"
            };

            var content = new FormUrlEncodedContent(postData);

            if (!string.IsNullOrEmpty(xsrfFromPage))
                client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", xsrfFromPage);

            var loginUrl = $"https://{tenant}.mijndiad.nl/login";
            var response = await client.PostAsync(loginUrl, content);
            Console.WriteLine($"  Login response status: {response.StatusCode}");

            string sessionCookie = null;
            string xsrfToken = null;
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    if (cookie.Contains($"{tenant}_session="))
                        sessionCookie = ExtractCookieValue(cookie, $"{tenant}_session=");
                    if (cookie.Contains("XSRF-TOKEN="))
                        xsrfToken = ExtractCookieValue(cookie, "XSRF-TOKEN=");
                }
            }

            return (sessionCookie, xsrfToken);
        }

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

            var bytes = new List<byte>();
            for (int i = 0; i < bits.Length; i += 8)
            {
                int length = Math.Min(8, bits.Length - i);
                string segment = bits.Substring(i, length);
                if (segment.Length == 8)
                    bytes.Add(Convert.ToByte(segment, 2));
            }

            return bytes.ToArray();
        }
    }
}
