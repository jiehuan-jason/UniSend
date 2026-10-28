using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography.Certificates;
using Windows.Storage.Streams;
using Windows.Web.Http;
using Windows.Web.Http.Filters;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using UniSend.Models;

namespace UniSend.Services
{
    public class LocalSendDiscoveryService : IDisposable
    {
        private const string MulticastAddress = "224.0.0.167";
        private const string MulticastPort = "53317";
        private DatagramSocket _udpSocket;
        private DataWriter _writer;

        public string Fingerprint { get; set; }
        public string DeviceAlias { get; set; } = "UWP-UniSend";

        public event Action<DeviceDto> DeviceDiscovered;

        public async Task StartAsync(string fingerprint)
        {
            Fingerprint = fingerprint;

            _udpSocket = new DatagramSocket();
            _udpSocket.MessageReceived += OnUdpMessageReceived;

            await _udpSocket.BindServiceNameAsync(MulticastPort);
            _udpSocket.JoinMulticastGroup(new Windows.Networking.HostName(MulticastAddress));

            var stream = await _udpSocket.GetOutputStreamAsync(new Windows.Networking.HostName(MulticastAddress), MulticastPort);
            _writer = new DataWriter(stream);

            await SendAnnouncementAsync(announce: true);
        }

        public async Task SendAnnouncementAsync(bool announce = true)
        {
            if (_writer == null) return;

            // 广播 protocol 设置为 https
            var announceDto = new
            {
                alias = DeviceAlias,
                version = "2.1",
                deviceModel = "Windows",
                deviceType = "desktop",
                fingerprint = Fingerprint,
                port = 53317,
                protocol = "http",
                download = false,
                announcement = announce,
                announce = announce
            };

            string json = JsonConvert.SerializeObject(announceDto);
            byte[] bytes = Encoding.UTF8.GetBytes(json);

            _writer.WriteBytes(bytes);
            await _writer.StoreAsync();
        }

        private void OnUdpMessageReceived(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            //System.Diagnostics.Debug.WriteLine($"[UDP收到数据] 来自: {args.RemoteAddress.CanonicalName}");
            try
            {
                using (var reader = args.GetDataReader())
                {
                    reader.UnicodeEncoding = Windows.Storage.Streams.UnicodeEncoding.Utf8;
                    string json = reader.ReadString(reader.UnconsumedBufferLength);

                    JObject root = JObject.Parse(json);

                    // 过滤本机指纹
                    string fp = (string)root["fingerprint"];
                    if (!string.IsNullOrEmpty(fp) && fp == Fingerprint) return;

                    string targetIp = args.RemoteAddress.CanonicalName;
                    int targetPort = (int?)root["port"] ?? 53317;
                    string protocol = (string)root["protocol"] ?? "https";

                    var device = new DeviceDto
                    {
                        Ip = targetIp,
                        Port = targetPort,
                        Alias = (string)root["alias"] ?? "Unknown Device",
                        DeviceModel = (string)root["deviceModel"],
                        DeviceType = (string)root["deviceType"],
                        Fingerprint = fp,
                        Protocol = protocol
                    };

                    DeviceDiscovered?.Invoke(device);

                    // 如果对端宣告新加入局域网，向其进行 HTTPS 反向注册
                    bool isAnnounce = (bool?)root["announce"] ?? (bool?)root["announcement"] ?? false;
                    if (isAnnounce)
                    {
                        _ = Task.Run(() => DiscoverDeviceByHttpAsync(targetIp, targetPort, protocol));
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// 支持通过 HTTPS / HTTP 向指定设备注册
        /// </summary>
        public async Task<DeviceDto> DiscoverDeviceByHttpAsync(string targetIp, int targetPort = 53317, string protocol = "https", int timeoutSeconds = 2)
        {
            try
            {
                var filter = new HttpBaseProtocolFilter();
                // 关键：在 10586 下对自签名证书必须加入所有可能的链错误忽略
                filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
                filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
                filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);
                filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.WrongUsage);
                filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.RevocationFailure);

                using (var client = new HttpClient(filter))
                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))
                {
                    var regDto = new
                    {
                        alias = DeviceAlias,
                        version = "2.0",
                        deviceModel = "Windows",
                        deviceType = "desktop",
                        fingerprint = Fingerprint,
                        port = 53317,
                        protocol = "http",
                        download = false
                    };

                    string jsonReq = JsonConvert.SerializeObject(regDto);
                    var content = new HttpStringContent(
                        jsonReq,
                        Windows.Storage.Streams.UnicodeEncoding.Utf8,
                        "application/json");

                    var uri = new Uri($"{protocol}://{targetIp}:{targetPort}/api/localsend/v2/register");

                    var response = await client.PostAsync(uri, content).AsTask(cts.Token);

                    if (response.IsSuccessStatusCode)
                    {
                        string responseBody = await response.Content.ReadAsStringAsync().AsTask(cts.Token);
                        JObject respObj = JObject.Parse(responseBody);

                        var discoveredDevice = new DeviceDto
                        {
                            Ip = targetIp,
                            Port = targetPort,
                            Alias = (string)respObj["alias"] ?? "Unknown Device",
                            DeviceModel = (string)respObj["deviceModel"],
                            DeviceType = (string)respObj["deviceType"],
                            Fingerprint = (string)respObj["fingerprint"],
                            Protocol = protocol
                        };

                        DeviceDiscovered?.Invoke(discoveredDevice);
                        return discoveredDevice;
                    }
                    else
                    {
                        //System.Diagnostics.Debug.WriteLine($"[HTTP反向注册失败] HTTP 状态码: {response.StatusCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                // 打印出具体哪里抛异常了，不要直接吃掉
                //System.Diagnostics.Debug.WriteLine($"[HTTP注册异常] IP: {targetIp}, 错误: {ex.Message}");
            }

            return null;
        }

        public void Dispose()
        {
            _udpSocket?.Dispose();
            _writer?.Dispose();
        }
    }
}