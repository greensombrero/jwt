using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Greensombrero.Jwt
{
    /// <summary>
    /// Implementation of IJwtSignatureKey when using the HMAC SHA-256 algorithm HS256.
    /// </summary>
    /// <remarks>This class is not thread safe.</remarks>
    public class HS256 : IJwtSignatureKey
    {
        private readonly HMACSHA256 _hmac;

        /// <summary>
        /// Initializes a new instance of the <see cref="HS256"/> class.
        /// </summary>
        /// <param name="secret">Secret to use in generating signatures</param>
        public HS256(byte[] secret)
        {
            _hmac = new HMACSHA256(secret);
        }

        /// <summary>
        /// Gets the algorithm the key supports.  This will be the JWT header alg value.
        /// </summary>
        public string Algorithm
        {
            get
            {
                return "HS256";
            }
        }

        /// <summary>
        /// Gets a value indicating whether the key can be used for signing or only verifying.  This is relevant when dealing with asymmetric signatures.
        /// </summary>
        public bool CanSign
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// Disposes of the underlying resources.
        /// </summary>
        public void Dispose()
        {
            _hmac.Dispose();
        }

        /// <summary>
        /// Generates the signature for the encoded token.
        /// </summary>
        /// <param name="encodedToken">The encoded token consisting of the header and claims</param>
        /// <returns>Returns the signature.</returns>
        public byte[] GenerateSignature(string encodedToken)
        {
            if (string.IsNullOrWhiteSpace(encodedToken))
            {
                throw new ArgumentNullException("encodedToken");
            }

            return _hmac.ComputeHash(Encoding.ASCII.GetBytes(encodedToken));
        }

        /// <summary>
        /// Determines if the given signature is valid for the given encoded token.
        /// </summary>
        /// <param name="encodedToken">Encoded token without the signature</param>
        /// <param name="signatureBytes">Bytes of the signature</param>
        /// <returns>Returns true if the signature is valid, false otherwise.</returns>
        public bool IsSignatureValid(string encodedToken, byte[] signatureBytes)
        {
            if (string.IsNullOrWhiteSpace(encodedToken))
            {
                throw new ArgumentNullException("encodedToken");
            }

            if (signatureBytes == null)
            {
                throw new ArgumentNullException("signatureBytes");
            }

            // If our length is off abort now
            if (signatureBytes.Length != 32)
            {
                return false;
            }

            byte[] expectedBytes = GenerateSignature(encodedToken);

            for(int i = 0; i < expectedBytes.Length; ++i)
            {
                if (signatureBytes[i] != expectedBytes[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
