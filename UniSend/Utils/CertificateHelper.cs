using System;
using Windows.Security.Cryptography;

namespace UniSend.Services
{
    public static class DeviceIdentityHelper
    {
        /// <summary>
        /// 生成 64 位的随机 Hex 字符串充当局域网指纹（纯原生，零外部依赖）
        /// </summary>
        public static string GenerateFingerprint()
        {
            // 生成 32 字节随机数 (256-bit)
            var buffer = CryptographicBuffer.GenerateRandom(32);
            string hex = CryptographicBuffer.EncodeToHexString(buffer);
            return hex.ToUpperInvariant();
        }
    }
}