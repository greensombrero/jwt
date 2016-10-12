using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Greensombrero.Jwt
{
    /// <summary>
    /// Service for working with JWT tokens.
    /// </summary>
    public class JwtService : IJwtService
    {
        /// <summary>
        /// Generates a new JWT token using just standard headers.
        /// </summary>
        /// <param name="claims">Claims to embed in token</param>
        /// <param name="key">Key to use to sign token</param>
        /// <returns>Returns token</returns>
        public string Generate(Dictionary<string, object> claims, IJwtSignatureKey key)
        {
            string baseToken = BuildHeader(key.Algorithm) + "." + SerializeData(claims);

            return baseToken + "." + Base64UrlEncoding.Encode(key.GenerateSignature(baseToken));
        }

        private string BuildHeader(string algorithm)
        {
            Dictionary<string, object> headerValues = new Dictionary<string, object>()
            {
                { "typ", "JWT" }
            };
            headerValues.Add("alg", algorithm);

            return SerializeData(headerValues);
        }

        private string SerializeData(object data)
        {
            return Base64UrlEncoding.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(data)));
        }
    }
}
