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

        var url = "api.coinbase.com/api/v3/brokerage/product_book";

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
                { "nonce", Guid.NewGuid()}
            },
            Claims = new Dictionary<string, object>
            {
                { "sub", keyName },
                { "uri", $"GET {url}" }
            },
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256)
        });

        Console.WriteLine($"Generated JWT: {token}");

        var client = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Get, $"https://{url}?product_id=ETH-USD&limit=100");
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
}
