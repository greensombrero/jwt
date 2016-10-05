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
    /// Contains unit tests of the HmacSha256Key.
    /// </summary>
    [TestFixture]
    public class HS256KeyTests
    {
        /// <summary>
        /// Tests that the proper property values are returned.
        /// </summary>
        [Test]
        public void Properties()
        {
            byte[] keyBytes = new byte[] { 1, 2, 3, 4 };
            using (IJwtSignatureKey key = new HS256(keyBytes))
            {
                Assert.AreEqual("HS256", key.Algorithm, "Algorithm");
                Assert.IsTrue(key.CanSign, "CanSign off");
            }  
        }

        /// <summary>
        /// Tests the happy path of generating a signature.  We compare against a well known expected signature value.
        /// </summary>
        [Test]
        public void GenerateSignature_HappyPath()
        {
            string expected = "BW5u0jLoX2kEz8KIK-O8WGGdSATEQ1-0hHJk3Gl6ThM";
            string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6Ik5Vbml0In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlkIjoxMjM0NTZ9";
            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("secret")))
            {
                Assert.AreEqual(expected, Convert.ToBase64String(key.GenerateSignature(token)).Replace("+", "-").Split('=')[0]);
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
            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("nunit")))
            {
                Assert.Throws<ArgumentNullException>(() => key.GenerateSignature(input));
            }
        }

        /// <summary>
        /// Tests the happy path for IsSignatureValid.
        /// </summary>
        [Test]
        public void IsSignatureValid_HappyPath()
        {
            byte[] secret = new byte[64];
            Random random = new Random();
            random.NextBytes(secret);

            string input = "SomeCoolInput";
            using (IJwtSignatureKey key = new HS256(secret))
            {
                Assert.IsTrue(key.IsSignatureValid(input, key.GenerateSignature(input)));
            }
        }

        /// <summary>
        /// Tests if the length of the signature bytes is off then false is returned.
        /// </summary>
        /// <param name="length">Length of signature to test with.</param>
        [TestCase(31)]
        [TestCase(33)]
        [TestCase(5)]
        public void IsSignatureValid_LengthOff(int length)
        {
            byte[] signature = new byte[length];
            Random random = new Random();
            random.NextBytes(signature);

            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("nunittest")))
            {
                Assert.IsFalse(key.IsSignatureValid("Testing123", signature));
            }
        }

        /// <summary>
        /// Tests if the input is different then false is returned.
        /// </summary>
        [Test]
        public void IsSignatureValid_InputDifferent()
        {
            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("nunittest")))
            {
                byte[] signature = key.GenerateSignature("Testing12");

                Assert.IsFalse(key.IsSignatureValid("Testing123", signature));
            }
        }

        /// <summary>
        /// Tests if the secrets are different then false is returned.
        /// </summary>
        [Test]
        public void IsSignatureValid_SecretDifferent()
        {
            string input = "abc123nunitrocks";

            byte[] signature;
            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("Secret1")))
            {
                signature = key.GenerateSignature(input);
            }

            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("Secret2")))
            {
                Assert.IsFalse(key.IsSignatureValid(input, signature));
            }
        }

        /// <summary>
        /// This validates that if any byte is off false is returned.
        /// </summary>
        [Test]
        public void IsSignatureValid_CheckEachByte()
        {
            string input = "abc123nunitrocks";

            byte[] signature;
            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("Secret1")))
            {
                signature = key.GenerateSignature(input);

                for (int i = 0; i < 32; ++i)
                {
                    byte[] modSignature = new byte[32];
                    signature.CopyTo(modSignature, 0);
                    modSignature[i] = (byte)(signature[i] + 1);
                    Assert.IsFalse(key.IsSignatureValid(input, modSignature));
                }
            }
        }

        /// <summary>
        /// Tests if the passed in token is null, empty, or whitespace then an ArgumentNullException is thrown.
        /// </summary>
        /// <param name="input">Input to test with</param>
        [TestCase(null)]
        [TestCase("")]
        [TestCase("   ")]
        public void IsSignatureValid_NullToken(string input)
        {
            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("Secret")))
            {
                Assert.Throws<ArgumentNullException>(() => key.IsSignatureValid(input, Encoding.ASCII.GetBytes("Test")));
            }
        }

        /// <summary>
        /// Tests if the passed in signature is null then an ArgumentNullException is thrown.
        /// </summary>
        [Test]
        public void IsSignatureValid_NullSignature()
        {
            using (IJwtSignatureKey key = new HS256(Encoding.ASCII.GetBytes("Secret")))
            {
                Assert.Throws<ArgumentNullException>(() => key.IsSignatureValid("Test", null));
            }
        }
    }
}
