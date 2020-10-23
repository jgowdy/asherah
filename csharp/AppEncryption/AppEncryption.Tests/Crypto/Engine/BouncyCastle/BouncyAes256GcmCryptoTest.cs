using GoDaddy.Asherah.Crypto.Engine.BouncyCastle;

namespace GoDaddy.Asherah.AppEncryption.Tests.Crypto.Engine.BouncyCastle
{
    public class BouncyAes256GcmCryptoTest : GenericAeadCryptoTest
    {
        public BouncyAes256GcmCryptoTest(ConfigFixture configFixture)
            : base(new BouncyAes256GcmCrypto(configFixture.Configuration))
        {
        }
    }
}
