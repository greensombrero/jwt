using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Greensombrero.Jwt
{
    /// <summary>
    /// Implementation of IJwtSignatureKey when using the RSA SHA-256 algorithm RS256.
    /// </summary>
    /// <remarks>This class is not thread safe.</remarks>
    public class RS256Key : IJwtSignatureKey
    {
        private readonly RSACryptoServiceProvider _rsa;
        private readonly SHA256CryptoServiceProvider _hash;

        /// <summary>
        /// Initializes a new instance of the <see cref="RS256Key"/> class.
        /// </summary>
        /// <param name="rsa">RSACryptoServiceProvider to use</param>
        public RS256Key(RSACryptoServiceProvider rsa)
        {
            _rsa = rsa;
            _hash = new SHA256CryptoServiceProvider();
        }

        /// <summary>
        /// Gets the algorithm the key supports.  This will be the JWT header alg value.
        /// </summary>
        public string Algorithm
        {
            get
            {
                return "RS256";
            }
        }

        /// <summary>
        /// Gets a value indicating whether the key can be used for signing or only verifying.  This is relevant when dealing with asymmetric signatures.
        /// </summary>
        public bool CanSign
        {
            get
            {
                return !_rsa.PublicOnly;
            }
        }

        /// <summary>
        /// Disposes of underlying cryptography resources.
        /// </summary>
        public void Dispose()
        {
            _rsa.Dispose();
            _hash.Dispose();
        }

        /// <summary>
        /// Generates the signature for the encoded token.
        /// </summary>
        /// <param name="encodedToken">The encoded token consisting of the header and claims</param>
        /// <exception cref="System.ArgumentNullException">Thrown if the encodedToken is null, empty or whitespace</exception>
        /// <exception cref="System.InvalidOperationException">Thrown if CanSign is false</exception>
        /// <returns>Returns the signature.</returns>
        public byte[] GenerateSignature(string encodedToken)
        {
            if (string.IsNullOrWhiteSpace(encodedToken))
            {
                throw new ArgumentNullException("encodedToken");
            }

            if (!CanSign)
            {
                throw new InvalidOperationException("No private key information is available.");
            }

            return _rsa.SignData(Encoding.ASCII.GetBytes(encodedToken), _hash);
        }

        /// <summary>
        /// Determines if the given signature is valid for the given encoded token.
        /// </summary>
        /// <param name="encodedToken">Encoded token without the signature</param>
        /// <param name="signatureBytes">Bytes of the signature</param>
        /// <exception cref="System.ArgumentNullException">Thrown if the encodedToken is null, empty or whitespace or signatureBytes is null</exception>
        /// <returns>Returns true if the signature is valid, false otherwise.</returns>
        public bool IsSignatureValid(string encodedToken, byte[] signatureBytes)
        {
            if (string.IsNullOrWhiteSpace(encodedToken))
            {
                throw new ArgumentNullException("encodedToken");
            }

            if (signatureBytes == null || signatureBytes.Length == 0)
            {
                throw new ArgumentNullException("signatureBytes");
            }

            return _rsa.VerifyData(Encoding.ASCII.GetBytes(encodedToken), _hash, signatureBytes);
        }
    }
}
