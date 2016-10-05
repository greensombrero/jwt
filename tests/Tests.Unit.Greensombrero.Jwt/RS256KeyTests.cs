using Greensombrero.Jwt;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Tests.Unit.Greensombrero.Jwt
{
    /// <summary>
    /// Contains unit tests of the RS256Key class.
    /// </summary>
    [TestFixture]
    public class RS256KeyTests
    {
        private const string _privateKey = "<RSAKeyValue><Modulus>3ZWrUY0Y6IKN1qI4BhxR2C7oHVFgGPYkd38uGq1jQNSqEvJFcN93CYm16/G78FAFKWqwsJb3Wx+nbxDn6LtP4AhULB1H0K0g7/jLklDAHvI8yhOKlvoyvsUFPWtNxlJyh5JJXvkNKV/4Oo12e69f8QCuQ6NpEPl+cSvXIqUYBCs=</Modulus><Exponent>AQAB</Exponent><P>8sINkf+7d0NjhNvsqN/NgiyXa5Ui1UTlisG+LW9j44WOFwMFfHdb8tEXp8UwfiuTLue7lUkx7azCtBgLRa/N9w==</P><Q>6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQ==</Q><DP>ZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZw==</DP><DQ>CmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQ==</DQ><InverseQ>Lesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==</InverseQ><D>D+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2Ylk=</D></RSAKeyValue>";
        private const string _publicKey = "<RSAKeyValue><Modulus>3ZWrUY0Y6IKN1qI4BhxR2C7oHVFgGPYkd38uGq1jQNSqEvJFcN93CYm16/G78FAFKWqwsJb3Wx+nbxDn6LtP4AhULB1H0K0g7/jLklDAHvI8yhOKlvoyvsUFPWtNxlJyh5JJXvkNKV/4Oo12e69f8QCuQ6NpEPl+cSvXIqUYBCs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        /// <summary>
        /// Tests that the proper property values are returned if the private key is known.
        /// </summary>
        [Test]
        public void Properties_WithPrivateKey()
        {
            byte[] keyBytes = new byte[] { 1, 2, 3, 4 };
            using (IJwtSignatureKey key = new RS256Key(new RSACryptoServiceProvider(2048)))
            {
                Assert.AreEqual("RS256", key.Algorithm, "Algorithm");
                Assert.IsTrue(key.CanSign, "CanSign off");
            }
        }

        /// <summary>
        /// Tests that the proper property values are returned if the private key is not known.
        /// </summary>
        [Test]
        public void Properties_WithNoPrivateKey()
        {
            string publicKey;
            using (RSACryptoServiceProvider full = new RSACryptoServiceProvider(2048))
            {
                publicKey = full.ToXmlString(false);
            }

            RSACryptoServiceProvider publicOnly = new RSACryptoServiceProvider();
            publicOnly.FromXmlString(publicKey);

            byte[] keyBytes = new byte[] { 1, 2, 3, 4 };
            using (IJwtSignatureKey key = new RS256Key(publicOnly))
            {
                Assert.AreEqual("RS256", key.Algorithm, "Algorithm");
                Assert.IsFalse(key.CanSign, "CanSign off");
            }
        }

        /// <summary>
        /// Tests the happy path of generating a signature.  We compare against a well known expected signature value.
        /// </summary>
        [Test]
        public void GenerateSignature_HappyPath()
        {
            string expected = "EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE";
            string token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(_privateKey);

            using (IJwtSignatureKey key = new RS256Key(rsa))
            {
                Assert.AreEqual(expected, Convert.ToBase64String(key.GenerateSignature(token)).Replace("+", "-").Replace("/", "_").Split('=')[0]);
            }
        }

        /// <summary>
        /// Tests if an empty, null, or whitespace input is put in an ArgumentNullException is thrown.
        /// </summary>
        /// <param name="input">Input to test with</param>
        [TestCase(null)]
        [TestCase("")]
        [TestCase("   ")]
        public void GenerateSignature_EmptyInput(string input)
        {
            using (IJwtSignatureKey key = new RS256Key(new RSACryptoServiceProvider()))
            {
                Assert.Throws<ArgumentNullException>(() => key.GenerateSignature(input));
            }
        }

        /// <summary>
        /// Tests that if only a public key is present and you try to generate a signature then an InvalidOperationException is thrown.
        /// </summary>
        [Test]
        public void GenerateSignature_PublicKeyOnly()
        {
            string publicKey;
            using (RSACryptoServiceProvider full = new RSACryptoServiceProvider(2048))
            {
                publicKey = full.ToXmlString(false);
            }

            RSACryptoServiceProvider publicOnly = new RSACryptoServiceProvider();
            publicOnly.FromXmlString(publicKey);

            byte[] keyBytes = new byte[] { 1, 2, 3, 4 };
            using (IJwtSignatureKey key = new RS256Key(publicOnly))
            {
                Assert.Throws<InvalidOperationException>(() => key.GenerateSignature("Testing123"), "Exception not thrown");
            }
        }

        /// <summary>
        /// Tests the happy path when the signature is valid.
        /// </summary>
        [Test]
        public void IsSignatureValid_HappyPath()
        {
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider(2048);
            RSACryptoServiceProvider publicRsa = new RSACryptoServiceProvider();
            publicRsa.FromXmlString(privateRsa.ToXmlString(false));

            string input = "Hello This is a Test123";

            byte[] signature;
            using (IJwtSignatureKey privateKey = new RS256Key(privateRsa))
            {
                signature = privateKey.GenerateSignature(input);
            }

            using (IJwtSignatureKey publicKey = new RS256Key(publicRsa))
            {
                Assert.IsTrue(publicKey.IsSignatureValid(input, signature), "Didn't return true");
            }
        }

        /// <summary>
        /// Tests that if the inputs are different then false is returned.
        /// </summary>
        [Test]
        public void IsSignatureValid_DifferentInput()
        {
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider(2048);
            RSACryptoServiceProvider publicRsa = new RSACryptoServiceProvider();
            publicRsa.FromXmlString(privateRsa.ToXmlString(false));

            string input = "Hello This is a Test123";

            byte[] signature;
            using (IJwtSignatureKey privateKey = new RS256Key(privateRsa))
            {
                signature = privateKey.GenerateSignature(input);
            }

            using (IJwtSignatureKey publicKey = new RS256Key(publicRsa))
            {
                Assert.IsFalse(publicKey.IsSignatureValid("Hello This is a Test124", signature), "Didn't return False");
            }
        }

        /// <summary>
        /// Tests that if the inputs are different then false is returned.
        /// </summary>
        [Test]
        public void IsSignatureValid_DifferentKey()
        {
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider(2048);
            RSACryptoServiceProvider publicRsa = new RSACryptoServiceProvider();

            string input = "Hello This is a Test123";

            byte[] signature;
            using (IJwtSignatureKey privateKey = new RS256Key(privateRsa))
            {
                signature = privateKey.GenerateSignature(input);
            }

            using (IJwtSignatureKey publicKey = new RS256Key(publicRsa))
            {
                Assert.IsFalse(publicKey.IsSignatureValid(input, signature), "Didn't return False");
            }
        }

        /// <summary>
        /// Tests that if the signature is way off then false is returned.
        /// </summary>
        [Test]
        public void IsSignatureValid_SignatureWayOff()
        {
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider(2048);
            RSACryptoServiceProvider publicRsa = new RSACryptoServiceProvider();
            publicRsa.FromXmlString(privateRsa.ToXmlString(false));

            string input = "Hello This is a Test123";

            byte[] signature;
            using (IJwtSignatureKey privateKey = new RS256Key(privateRsa))
            {
                signature = privateKey.GenerateSignature(input);
            }

            using (IJwtSignatureKey publicKey = new RS256Key(publicRsa))
            {
                Assert.IsFalse(publicKey.IsSignatureValid(input, new byte[] { 123 }), "Didn't return False");
            }
        }

        /// <summary>
        /// Tests that if the token is missing then an ArgumentNullException is thrown.
        /// </summary>
        /// <param name="input">Input to test with</param>
        [TestCase(null)]
        [TestCase("")]
        [TestCase("  ")]
        public void IsSignatureValid_TokenMissing(string input)
        {
            using (IJwtSignatureKey key = new RS256Key(new RSACryptoServiceProvider()))
            {
                Assert.Throws<ArgumentNullException>(() => key.IsSignatureValid(input, new byte[] { }));
            }
        }

        /// <summary>
        /// Tests that if the signature bytes are null then an ArgumentNullException is thrown.
        /// </summary>
        [Test]
        public void IsSignatureValid_SignatureMissing()
        {
            using (IJwtSignatureKey key = new RS256Key(new RSACryptoServiceProvider()))
            {
                Assert.Throws<ArgumentNullException>(() => key.IsSignatureValid("Test", null));
            }
        }

        /// <summary>
        /// Tests that if the signature bytes are empty then an ArgumentNullException is thrown.
        /// </summary>
        [Test]
        public void IsSignatureValid_SignatureEmpty()
        {
            using (IJwtSignatureKey key = new RS256Key(new RSACryptoServiceProvider()))
            {
                Assert.Throws<ArgumentNullException>(() => key.IsSignatureValid("Test", new byte[] { }));
            }
        }
    }
}
