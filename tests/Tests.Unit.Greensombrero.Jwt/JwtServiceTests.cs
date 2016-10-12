using Greensombrero.Jwt;
using Moq;
using Newtonsoft.Json;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tests.Unit.Greensombrero.Jwt
{
    /// <summary>
    /// Contains unit tests of the JwtService.
    /// </summary>
    [TestFixture]
    public class JwtServiceTests
    {
        public JwtService BuildInstance()
        {
            return new JwtService();
        }

        /// <summary>
        /// Tests that generate will generate an expected token when using basic headers and claims.
        /// </summary>
        [Test]
        public void Generate_BasicHeadersAndClaims()
        {
            IJwtService service = BuildInstance();

            Mock<IJwtSignatureKey> key = new Mock<IJwtSignatureKey>();
            key.Setup(k => k.Algorithm).Returns("HS256");
            key.Setup(k => k.CanSign).Returns(true);

            byte[] signature = new byte[] { 1, 2, 3, 5, 8, 13, 21 };
            string capturedEncodedToken = null;
            key.Setup(k => k.GenerateSignature(It.IsNotNull<string>())).Callback<string>(c => { capturedEncodedToken = c; }).Returns(signature);
            string signatureString = Base64UrlEncoding.Encode(signature);

            Dictionary<string, object> expectedClaims = new Dictionary<string, object>()
            {
                { "sub", "MySubject" },
                { "uid", 123456 },
                { "admin", true }
            };

            string token = service.Generate(expectedClaims, key.Object);

            Assert.IsNotNull(token, "Null returned");
            string[] elements = token.Split('.');
            Assert.AreEqual(3, elements.Length, "Token doesn't contain 3 segments");

            Dictionary<string, object> header = JsonConvert.DeserializeObject<Dictionary<string, object>>(Encoding.UTF8.GetString(Base64UrlEncoding.Decode(elements[0])));

            Assert.AreEqual(2, header.Count, "Header count off");
            Assert.AreEqual("HS256", header["alg"], "alg off");
            Assert.AreEqual("JWT", header["typ"], "typ off");

            Dictionary<string, object> claims = JsonConvert.DeserializeObject<Dictionary<string, object>>(Encoding.UTF8.GetString(Base64UrlEncoding.Decode(elements[1])));
            Assert.AreEqual(3, claims.Count, "Claims count off");
            Assert.AreEqual("MySubject", claims["sub"], "sub claim off");
            Assert.AreEqual(123456, claims["uid"], "uid claim off");
            Assert.AreEqual(true, claims["admin"], "admin claim off");

            Assert.AreEqual(signatureString, elements[2], "Signature off");
            Assert.AreEqual(capturedEncodedToken, elements[0] + "." + elements[1], "Captured encoded token");
        }
    }
}
