using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Greensombrero.Jwt
{
    /// <summary>
    /// Interface exposed by keys used to sign and verify signatures of JWT tokens.
    /// </summary>
    public interface IJwtSignatureKey : IDisposable
    {
        /// <summary>
        /// Gets the algorithm the key supports.  This will be the JWT header alg value.
        /// </summary>
        string Algorithm { get; }

        /// <summary>
        /// Gets a value indicating whether the key can be used for signing or only verifying.  This is relevant when dealing with asymmetric signatures.
        /// </summary>
        bool CanSign { get; }

        /// <summary>
        /// Generates the signature for the encoded token.
        /// </summary>
        /// <param name="encodedToken">The encoded token consisting of the header and claims</param>
        /// <exception cref="System.ArgumentNullException">Thrown if the encodedToken is null, empty or whitespace</exception>
        /// <exception cref="System.InvalidOperationException">Thrown if CanSign is false</exception>
        /// <returns>Returns the signature.</returns>
        byte[] GenerateSignature(string encodedToken);

        /// <summary>
        /// Determines if the given signature is valid for the given encoded token.
        /// </summary>
        /// <param name="encodedToken">Encoded token without the signature</param>
        /// <param name="signatureBytes">Bytes of the signature</param>
        /// <exception cref="System.ArgumentNullException">Thrown if the encodedToken is null, empty or whitespace or signatureBytes is null</exception>
        /// <returns>Returns true if the signature is valid, false otherwise.</returns>
        bool IsSignatureValid(string encodedToken, byte[] signatureBytes);
    }
}
