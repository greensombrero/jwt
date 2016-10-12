using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Greensombrero.Jwt
{
    /// <summary>
    /// Interface exposed by service for working with JWT tokens.
    /// </summary>
    public interface IJwtService
    {
        /// <summary>
        /// Generates a new JWT token using just standard headers.
        /// </summary>
        /// <param name="claims">Claims to embed in token</param>
        /// <param name="key">Key to use to sign token</param>
        /// <returns>Returns token</returns>
        string Generate(Dictionary<string, object> claims, IJwtSignatureKey key);
    }
}
