using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using Microsoft.IdentityModel.Tokens;

namespace WebApplication3
{
    public class TestHarness
    {
        public static void Run()
        {
            var handler = new HelixJwtSecurityTokenHandler();

            SignatureValidator signatureValidator = (token, validationParameters) =>
            {
                var segments = token.Split('.');
                if (segments.Length < 3)
                {
                    throw new Exception("JSON token format is invalid. Expected: headerSegment.claimsSegment.verificationSignatureSegment[.encryptionKeySegment].");
                }

                var headerSegment = segments[0];
                var claimSegment = segments[1];
                var signatureSegment = segments[2];

                var headerJson = JwtHeader.Base64UrlDeserialize(headerSegment);

                var jwt = new JwtSecurityToken(headerJson, new JwtPayload(), headerSegment, claimSegment, signatureSegment);

                // snip: verify the signature

                // snip: check if encrypted and retrieve the encryption key

                var base64Encoder = new Base64Encoder();
                byte[] claimBytes = base64Encoder.Decode(claimSegment);

                // snip: enflate and decrypt the payload, if necessary
                var claimJson = Read(claimBytes);


                var payload = JwtPayload.Deserialize(claimJson);

                // fix 'exp', 'nbf' and 'iat' claim values
                // HACK: workaround the bug https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/490
                Action<string> convertDateTimeClaimToInt = claimName =>
                {
                    if (payload.ContainsKey(claimName))
                    {
                        payload[claimName] = (int)double.Parse((string)payload[claimName]);
                    }
                };
                convertDateTimeClaimToInt("exp");
                convertDateTimeClaimToInt("nbf");
                convertDateTimeClaimToInt("iat");

                foreach (var key in payload.Keys)
                {
                    jwt.Payload.Add(key, payload[key]);
                }

                return jwt;
            };

            var tokenValidationParameters = new TokenValidationParameters
            {
                // The signing key must match!
                ValidateIssuerSigningKey = true,
                //IssuerSigningKey = cert,

                // Validate the JWT Issuer (iss) claim
                ValidateIssuer = false,

                // Validate the JWT Audience (aud) claim
                ValidateAudience = false,
                ValidAudiences = new[] { "*" }, // or can provide own AudienceValidator handler

                // Validate the token expiry
                ValidateLifetime = false,

                // If you want to allow a certain amount of clock drift, set that here:
                ClockSkew = TimeSpan.Zero,

                RequireSignedTokens = true,

                SignatureValidator = signatureValidator
            };

            var rawJwt = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImlzRW5jcnlwdGVkIjoiRmFsc2UiLCJ4NXQiOiI1M0VENjE1NTUwNTlBRDg3QUE4MkNBNTYwRTQ4QkIxMkM1MzdGOUY1IiwidmVyIjoiMi4xIn0.eyJhdWQiOiJIZWxpeC5TZWN1cml0eS5VdGlsIiwiaWF0IjoiMTQ4MDM5ODEyNy44MTY1NiIsIm5iZiI6IjE0ODAzOTgwNjYuODIxNzkiLCJDbGFpbVNldHMiOlt7IkNsYWltcyI6eyJzZXJ2ZXJJZCI6IkhlbGl4LkNvbnRhaW5lcnMuRGV2Iiwic2VydmVyVmVyc2lvbiI6ImRldiIsImlzc1g1dCI6IjUzRUQ2MTU1NTA1OUFEODdBQTgyQ0E1NjBFNDhCQjEyQzUzN0Y5RjUifSwiUHJvdmlkZXIiOiJIZWxpeC5Db250YWluZXJzLkRldi52ZGV2IiwiU2NoZW1hIjoiSGVsaXguQ29udGFpbmVyIiwiVmVyc2lvbiI6IlYxIn1dLCJpc3MiOiJIZWxpeC5Db250YWluZXJzLkRldi52ZGV2IiwiZXhwIjoiMTQ4MDM5OTI2Ni44MjI3OSIsInNzaWQiOiJlYTQ1YTMwYzVhNTA0MTZhYjY0MzAzNjBkOGQ3YzFiMyIsImp0aSI6IjgwYTM0OTg0LWI5YmItNGRjZi05MmQyLTM2ZTAyMWI2Nzc4ZiJ9.";

            SecurityToken validatedToken;
            var principal = handler.ValidateToken(rawJwt, tokenValidationParameters, out validatedToken);

            var claims = principal.Identities.First().Claims.ToList();
            var claim = claims.First(c => c.Type == "ClaimSets");
        }



        private static string Read(byte[] input)
        {
            string output;
            using (var memoryStream = new MemoryStream(input))
            {
                using (var reader = new StreamReader(memoryStream))
                {
                    output = reader.ReadToEnd();
                }
            }
            return output;
        }

        private sealed class Base64Encoder
        {
            public byte[] Decode(string arg)
            {
                // This code has been extracted from the Microsoft.Json library and is being left in its current state to ensure consistency between Helix and its consumers.

                arg = arg.Replace('-', '+'); // 62nd char of encoding
                arg = arg.Replace('_', '/'); // 63rd char of encoding
                                             // Pad with trailing '='s
                switch (arg.Length % 4)
                {
                    case 0:
                        break; // No pad chars in this case
                    case 2:
                        arg += "==";
                        break; // Two pad chars
                    case 3:
                        arg += "=";
                        break; // One pad char
                    default:
                        throw new Exception("Invalid base 64 string");
                }

                var data = Convert.FromBase64String(arg); // standard base64 decoder
                return data;
            }
        }

    }
}
