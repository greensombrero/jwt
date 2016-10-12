using Greensombrero.Jwt;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tests.Unit.Greensombrero.Jwt
{
    /// <summary>
    /// Contains unit tests of the Base64UrlEncoding class.
    /// </summary>
    [TestFixture]
    public class Base64UrlEncodingTests
    {
        /// <summary>
        /// Tests that encode returns a string.
        /// </summary>
        [Test]
        public void Encode_HappyPath()
        {
            byte[] data = new byte[] { 123, 45, 133, 34, 28, 74 };

            Assert.IsNotNull(Base64UrlEncoding.Encode(data), "Null returned");
        }

        /// <summary>
        /// Tests that decode returns the proper data.
        /// </summary>
        [Test]
        public void Decode_HappyPath()
        {
            byte[] data = new byte[] { 123, 45, 133, 34, 28, 74 };

            CollectionAssert.AreEqual(data, Base64UrlEncoding.Decode(Base64UrlEncoding.Encode(data)), "Decode failed");
        }
    }
}
