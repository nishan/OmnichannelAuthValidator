using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Globalization;


namespace OmnichannelAuthValidator
{
    class Program
    {

		private const string pemPubKeyHeader = "-----BEGIN PUBLIC KEY-----";
		private const string pemPubKeyFooter = "-----END PUBLIC KEY-----";
		static  async Task Main(string[] args)
        {
            // Change these variables
            string token = "<token>";
            string publickKeyURL = "https://yourpublickkeyurl";
            //----

            Uri u = new Uri(publickKeyURL);
            string pkey4 = await GetPublicKeyFromEndpoint(u);
			ValidateTokenAsync(token, pkey4);
        }

        public static ClaimsPrincipal ValidateTokenAsync(string token, string publicKey)
        {
            ClaimsPrincipal claims = null;           
            var keyBytes = Convert.FromBase64String(publicKey); // your key here
            var rsa = RSAUtils.DecodePublicKey(keyBytes);
            var validationParameters = new TokenValidationParameters()
            {
                RequireExpirationTime = false,
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidateIssuer = false,
                IssuerSigningKey = new RsaSecurityKey(rsa)
            };
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultInboundClaimFilter.Clear();
               
            claims = handler.ValidateToken(token, validationParameters, out var validatedToken);
                
            return claims;
		}

		private static async Task<string> GetPublicKeyFromEndpoint(Uri publicKeyEndpoint)
		{
            string publicKey = null;
            
                publicKey = await new HttpClient().GetStringAsync(publicKeyEndpoint).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(publicKey))
                {
                    publicKey = TrimPEMKey(publicKey);
				}

				publicKey = RemoveKeyPadding(publicKey);
           
            return publicKey;
        }

		private static string TrimPEMKey(string key)
		{
			key = key.Replace(pemPubKeyHeader, "");
			key = key.Replace(pemPubKeyFooter, "");
			key = key.Trim();

			return key;
		}

		private static string RemoveKeyPadding(string publicKey)
		{
			 publicKey = Regex.Replace(publicKey, @"\t|\n|\r", "");
			var modulus = Base64UrlEncoder.DecodeBytes(publicKey);
			if (modulus.Length == 257 && modulus[0] == 0)
			{
				var newModulus = new byte[256];
				Array.Copy(modulus, 1, newModulus, 0, 256);
				publicKey = Base64UrlEncoder.Encode(newModulus);
			}

			return publicKey;
		}

	}
}
