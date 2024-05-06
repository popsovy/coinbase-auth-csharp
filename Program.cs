using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Headers;
using System.Security.Cryptography;

internal class Program
{
    static async Task Main()
    {
        var keyName = "organizations/{org_id}/apiKeys/{key_id}";
        var privateKeyPem = "-----BEGIN EC PRIVATE KEY-----\nYOUR PRIVATE KEY\n-----END EC PRIVATE KEY-----\n";

        using var privateKey = LoadPrivateKey(privateKeyPem);
        var securityKey = new ECDsaSecurityKey(privateKey) { KeyId = keyName };

        var now = DateTime.UtcNow;
        var handler = new JsonWebTokenHandler();

        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "coinbase-cloud",
            NotBefore = now,
            Expires = now.AddMinutes(2),
            TokenType = "JWT",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                { "nonce", GenerateRandomHex(16)}
            },
            Claims = new Dictionary<string, object>
            {
                { "sub", keyName },
                { "uri", "GET api.coinbase.com/api/v3/brokerage/accounts" }
            },
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256)
        });

        Console.WriteLine($"Generated JWT: {token}");

        var client = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://api.coinbase.com/api/v3/brokerage/accounts");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        try
        {
            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            Console.WriteLine(await response.Content.ReadAsStringAsync());
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"Request error: {e.Message}, Status Code: {e.StatusCode}");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error: {e.Message}");
        }
    }

    static ECDsa LoadPrivateKey(string pem)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);

        return ecdsa;
    }

    static string GenerateRandomHex(int byteLength)
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = RandomNumberGenerator.GetBytes(byteLength);

        return BitConverter.ToString(bytes).Replace("-", "").ToLower();
    }
}
