using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Greensombrero.Jwt
{
    /// <summary>
    /// Utility class for doing Base64 Url encoding.
    /// </summary>
    public static class Base64UrlEncoding
    {
        /// <summary>
        /// Encodes the given array of bytes using Base64 URL encoding.
        /// </summary>
        /// <param name="data">Data to encode</param>
        /// <returns>Returns the encoded string</returns>
        public static string Encode(byte[] data)
        {
            return Convert.ToBase64String(data).Split('=')[0].Replace('+', '-').Replace('/', '_');
        }

        /// <summary>
        /// Decodes the given string using Base64 URL encoding.
        /// </summary>
        /// <param name="input">Data to decode</param>
        /// <returns>Returns the decoded string</returns>
        public static byte[] Decode(string input)
        {
            string normalBase64 = input.Replace('-', '+').Replace('_', '/');
            switch (normalBase64.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    normalBase64 = normalBase64 + "==";
                    break;
                case 3:
                    normalBase64 = normalBase64 + "=";
                    break;
                default:
                    throw new NotImplementedException();
            }

            return Convert.FromBase64String(normalBase64);
        }
    }
}
