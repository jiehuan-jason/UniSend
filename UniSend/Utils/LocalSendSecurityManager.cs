using System;
using System.IO;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Certificates;
using Windows.Security.Cryptography.Core;

// 引入 BouncyCastle 相关命名空间
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities;

namespace UniSend.Utils
{
    public static class LocalSendSecurityManager
    {
        private const string CertFriendlyName = "LocalSend_Client_Cert";
        private static Certificate _cachedCert;
        private static string _cachedFingerprint;

        /// <summary>
        /// 获取或动态创建客户端证书（供 HttpBaseProtocolFilter 使用）
        /// </summary>
        public static async Task<Certificate> GetOrCreateClientCertificateAsync()
        {
            if (_cachedCert != null)
            {
                return _cachedCert;
            }

            try
            {
                // 1. 优先查询本地证书库是否已存在之前生成的证书
                var query = new CertificateQuery { FriendlyName = CertFriendlyName };
                var certs = await CertificateStores.FindAllAsync(query);
                if (certs.Count > 0)
                {
                    _cachedCert = certs[0];
                    _cachedFingerprint = CalculateFingerprint(_cachedCert);
                    return _cachedCert;
                }

                // 2. 本地不存在，使用 BouncyCastle 在内存中动态生成 RSA 密钥对与 X.509 证书
                var random = new Org.BouncyCastle.Security.SecureRandom();
                var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
                var keyPairGenerator = new RsaKeyPairGenerator();
                keyPairGenerator.Init(keyGenerationParameters);
                var keyPair = keyPairGenerator.GenerateKeyPair();

                var certGen = new X509V3CertificateGenerator();
                var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
                certGen.SetSerialNumber(serialNumber);

                var dn = new X509Name("CN=UniSendClient");
                certGen.SetIssuerDN(dn);
                certGen.SetSubjectDN(dn);
                certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
                certGen.SetNotAfter(DateTime.UtcNow.AddYears(10));
                certGen.SetPublicKey(keyPair.Public);

                // 添加扩展：支持客户端身份认证与服务端身份认证
                certGen.AddExtension(
                    X509Extensions.ExtendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(new[] { KeyPurposeID.IdKPClientAuth, KeyPurposeID.IdKPServerAuth }));

                // 使用 SHA256 签名生成证书
                ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", keyPair.Private, random);
                var newCert = certGen.Generate(signatureFactory);

                // 3. 将证书与私钥打包成 PKCS#12 (PFX) 内存字节流
                var pkcs12Store = new Pkcs12StoreBuilder().Build();
                var certEntry = new X509CertificateEntry(newCert);
                pkcs12Store.SetCertificateEntry("LocalSendClient", certEntry);
                pkcs12Store.SetKeyEntry("LocalSendClient", new AsymmetricKeyEntry(keyPair.Private), new[] { certEntry });

                string tempPassword = Guid.NewGuid().ToString("N");
                byte[] pfxBytes;
                using (var mem = new MemoryStream())
                {
                    pkcs12Store.Save(mem, tempPassword.ToCharArray(), random);
                    pfxBytes = mem.ToArray();
                }

                // 4. 将生成的 PFX 导入到当前 UWP 应用的沙箱证书库
                string pfxBase64 = Convert.ToBase64String(pfxBytes);
                await CertificateEnrollmentManager.ImportPfxDataAsync(
                    pfxBase64,
                    tempPassword,
                    ExportOption.Exportable,
                    KeyProtectionLevel.NoConsent,
                    InstallOptions.None,
                    CertFriendlyName
                );

                // 5. 导入完成后从证书库获取并缓存
                var loadedCerts = await CertificateStores.FindAllAsync(query);
                if (loadedCerts.Count > 0)
                {
                    _cachedCert = loadedCerts[0];
                    _cachedFingerprint = CalculateFingerprint(_cachedCert);
                    return _cachedCert;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[生成/加载客户端证书异常]: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// 获取客户端证书对应的 SHA-256 小写指纹字符串
        /// </summary>
        public static async Task<string> GetFingerprintAsync()
        {
            if (string.IsNullOrEmpty(_cachedFingerprint))
            {
                await GetOrCreateClientCertificateAsync();
            }
            return _cachedFingerprint;
        }

        /// <summary>
        /// 计算证书原始二进制的 SHA-256 哈希
        /// </summary>
        private static string CalculateFingerprint(Certificate cert)
        {
            var rawBuffer = cert.GetCertificateBlob();
            var sha256 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            var hashedBuffer = sha256.HashData(rawBuffer);
            return CryptographicBuffer.EncodeToHexString(hashedBuffer).ToLowerInvariant();
        }
    }
}