using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace MijnDiadAutomation
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("== Dynamics → MijnDiAd Automation ==");

            if (args.Length == 0)
            {
                Console.WriteLine("Please provide the path to the JSON file as an argument.");
                return;
            }

            string jsonFilePath = args[0];
            if (!File.Exists(jsonFilePath))
            {
                Console.WriteLine($"File not found: {jsonFilePath}");
                return;
            }

            string clientJson = await File.ReadAllTextAsync(jsonFilePath);

            // Read credentials from environment variables
            string username = Environment.GetEnvironmentVariable("MIJNDIAD_USERNAME");
            string password = Environment.GetEnvironmentVariable("MIJNDIAD_PASSWORD");
            string totpSecret = Environment.GetEnvironmentVariable("MIJNDIAD_TOTP_SECRET");
            string tenant = Environment.GetEnvironmentVariable("MIJNDIAD_TENANT") ?? "lngvty";

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(totpSecret))
            {
                Console.WriteLine("Missing credentials. Set MIJNDIAD_USERNAME, MIJNDIAD_PASSWORD, and MIJNDIAD_TOTP_SECRET as GitHub secrets.");
                return;
            }

            using var client = new HttpClient();

            // Step 1: Login
            var loginData = new
            {
                email = username,
                password = password,
                totp_code = GenerateTOTP(totpSecret),
                tenant = tenant
            };

            var loginContent = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");
            var loginUrl = $"https://{tenant}.mijndiad.nl/api/login";

            HttpResponseMessage loginResponse;
            try
            {
                loginResponse = await client.PostAsync(loginUrl, loginContent);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Login request failed: {ex.Message}");
                return;
            }

            if (!loginResponse.IsSuccessStatusCode)
            {
                string responseBody = await loginResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"❌ Login failed. Status: {loginResponse.StatusCode}");
                Console.WriteLine(responseBody);
                return;
            }

            Console.WriteLine("✓ Login successful!");

            // Step 2: Post client JSON
            var content = new StringContent(clientJson, Encoding.UTF8, "application/json");
            var clientUrl = $"https://{tenant}.mijndiad.nl/api/clients";

            try
            {
                var response = await client.PostAsync(clientUrl, content);
                string result = await response.Content.ReadAsStringAsync();

                Console.WriteLine("MijnDiAd Response:");
                Console.WriteLine(result);

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("✓ Client created successfully!");
                    File.Delete(jsonFilePath);
                    Console.WriteLine($"✓ Deleted processed file: {jsonFilePath}");
                }
                else
                {
                    Console.WriteLine($"❌ Failed to create client. Status: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error posting client data: {ex.Message}");
            }
        }

        // TOTP generator (6-digit)
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

            using var hmac = new System.Security.Cryptography.HMACSHA1(secretBytes);
            byte[] hash = hmac.ComputeHash(counterBytes);

            int offset = hash[hash.Length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                       | ((hash[offset + 1] & 0xFF) << 16)
                       | ((hash[offset + 2] & 0xFF) << 8)
                       | (hash[offset + 3] & 0xFF);

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
                    bytes.Add(Convert.ToByte(segment, 2));
            }

            return bytes.ToArray();
        }
    }
}
