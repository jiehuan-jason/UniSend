using System;
using Windows.Security.Cryptography;
using Windows.Storage;

namespace UniSend.Services
{
    public static class DeviceIdentityHelper
    {
        public static string GenerateFingerprint()
        {
            // 生成 32 字节随机数 (256-bit)
            var buffer = CryptographicBuffer.GenerateRandom(32);
            string hex = CryptographicBuffer.EncodeToHexString(buffer);
            ApplicationDataContainer localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
            localSettings.Values["fingerprint"] = hex.ToUpperInvariant();
            return hex.ToUpperInvariant();
        }

        public static string GetFingerprint()
        {
            ApplicationDataContainer localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
            
            string localValue = localSettings.Values["fingerprint"] as string;

            if (localValue == null)
            {
                return GenerateFingerprint();
            }
            else return localValue;
        }
    }
}