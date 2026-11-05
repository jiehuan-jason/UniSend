using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking.Sockets;
using Windows.Storage;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using UniSend.Models;
using System.Collections.Generic;
using Windows.Security.ExchangeActiveSyncProvisioning;
using Windows.Storage.Pickers;
using Windows.Web.Http.Filters;
using Windows.Security.Cryptography.Certificates;
using Windows.Web.Http;
using UniSend.Utils;
using Windows.Storage.Streams;
using Windows.Web.Http.Headers;
using System.Linq;

namespace UniSend.Services
{


    public class LocalSendHttpServer : IDisposable
    {
        private StreamSocketListener _listener;

        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, string>> _activeSessions
            = new ConcurrentDictionary<string, ConcurrentDictionary<string, string>>();
        private readonly ConcurrentDictionary<string, string> _fileNames = new ConcurrentDictionary<string, string>();


        public string DeviceAlias { get; set; } = new EasClientDeviceInformation().FriendlyName + " UWP";
        public string Fingerprint { get; set; }
        public int Port { get; set; } = 53317;

        public event Action<DeviceDto> DeviceDiscovered;
        public event Action<ReceivedUploadFile> ReceivedTextFile;

        public async Task StartAsync(string fingerprint, int port = 53317)
        {
            Fingerprint = fingerprint;
            Port = port;

            _listener = new StreamSocketListener();
            _listener.ConnectionReceived += OnConnectionReceived;
            await _listener.BindServiceNameAsync(port.ToString());
        }

        private async void OnConnectionReceived(StreamSocketListener sender, StreamSocketListenerConnectionReceivedEventArgs args)
        {
            try
            {
                using (var inStream = args.Socket.InputStream.AsStreamForRead())
                using (var outStream = args.Socket.OutputStream.AsStreamForWrite())
                {
                    // 1. 读取完整的 HTTP Header（直到遇到 \r\n\r\n 为止）
                    var headerBytes = new System.Collections.Generic.List<byte>();
                    byte[] singleBuffer = new byte[1];
                    bool headerEnded = false;

                    while (!headerEnded)
                    {
                        int read = await inStream.ReadAsync(singleBuffer, 0, 1);
                        if (read == 0) return; // 对端关闭

                        headerBytes.Add(singleBuffer[0]);
                        int count = headerBytes.Count;
                        if (count >= 4 &&
                            headerBytes[count - 4] == '\r' &&
                            headerBytes[count - 3] == '\n' &&
                            headerBytes[count - 2] == '\r' &&
                            headerBytes[count - 1] == '\n')
                        {
                            headerEnded = true;
                        }

                        // 防止恶意超长请求头打爆内存
                        if (count > 8192) return;
                    }

                    string headerText = Encoding.UTF8.GetString(headerBytes.ToArray());
                    var lines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);
                    if (lines.Length == 0) return;

                    var reqParts = lines[0].Split(' ');
                    if (reqParts.Length < 2) return;

                    string method = reqParts[0];
                    string rawUrl = reqParts[1];

                    long contentLength = 0;
                    bool isChunked = false;
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                        {
                            long.TryParse(line.Substring(15).Trim(), out contentLength);
                        }
                        else if (line.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase) &&
                                    line.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            isChunked = true;
                        }
                    }

                    var uri = new Uri("http://localhost" + rawUrl);
                    string path = uri.AbsolutePath;

                    // 2. 路由匹配
                    if (method == "POST" && path == "/api/localsend/v2/register")
                    {
                        // 精准从原生底层流读取指定字节数的 JSON
                        string bodyJson = await ReadExactBytesAsStringAsync(inStream, contentLength);
                        string remoteIp = args.Socket.Information.RemoteAddress.CanonicalName;

                        if (!string.IsNullOrEmpty(bodyJson))
                        {
                            try
                            {
                                JObject root = JObject.Parse(bodyJson);
                                var discoveredDevice = new DeviceDto
                                {
                                    Ip = remoteIp,
                                    Port = (int?)root["port"] ?? 53317,
                                    Alias = (string)root["alias"] ?? "Unknown Device",
                                    DeviceModel = (string)root["deviceModel"],
                                    DeviceType = (string)root["deviceType"],
                                    Fingerprint = (string)root["fingerprint"],
                                    Protocol = (string)root["protocol"] ?? "http"
                                };

                                DeviceDiscovered?.Invoke(discoveredDevice);
                            }
                            catch { }
                        }

                        var responseObj = new
                        {
                            alias = DeviceAlias,
                            version = "2.0",
                            deviceModel = "Windows",
                            deviceType = "desktop",
                            fingerprint = Fingerprint,
                            protocol = "http",
                            download = false
                        };

                        string responseJson = JsonConvert.SerializeObject(responseObj);
                        await SendResponseAsync(outStream, "200 OK", "application/json", responseJson);
                    }
                    else if (method == "POST" && path == "/api/localsend/v2/prepare-upload")
                    {
                        string jsonBody = await ReadExactBytesAsStringAsync(inStream, contentLength);
                        if (string.IsNullOrEmpty(jsonBody))
                        {
                            await SendResponseAsync(outStream, "400 Bad Request", "application/json", "{}");
                            return;
                        }

                        await HandlePrepareUploadAsync(jsonBody, outStream);
                    }
                    else if (method == "POST" && path == "/api/localsend/v2/upload")
                    {
                        // 文件传输依然直接走底层 Stream
                        await HandleFileUploadAsync(uri.Query, inStream, isChunked, contentLength, outStream);
                    }
                    else
                    {
                        await SendResponseAsync(outStream, "404 Not Found", "text/plain", "Not Found");
                    }
                }
            }
            catch { }
        }

        private async Task HandlePrepareUploadAsync(string json, Stream outStream)
        {
            try
            {
                JObject root = JObject.Parse(json);
                var filesObj = root["files"] as JObject;
                var senderName = (string)root["info"]?["alias"] ?? "Unknown Device";
                if (filesObj == null)
                {
                    await SendResponseAsync(outStream, "400 Bad Request", "application/json", "{}");
                    return;
                }

                var filesList = new List<ReceivedUploadFile>();

                string sessionId = Guid.NewGuid().ToString();
                var tokenMap = new ConcurrentDictionary<string, string>();
                var responseFiles = new System.Collections.Generic.Dictionary<string, string>();

                foreach (var fileProp in filesObj.Properties())
                {
                    var id = fileProp.Name;
                    var token = Guid.NewGuid().ToString("N");
                    var name = (string)fileProp.Value["fileName"] ?? "received_file.bin";
                    var uploadFileObj = new ReceivedUploadFile
                    {
                        Id = id,
                        Name = name,
                        Token = token,
                        fileType = (string)fileProp.Value["fileType"],
                        Preview = !string.IsNullOrEmpty((string)fileProp.Value["preview"]) ? (string)fileProp.Value["preview"] : "",
                        SenderName = senderName,
                        stream = outStream
                    };

                    filesList.Add(uploadFileObj);

                    if (!uploadFileObj.Preview.Equals(""))
                    {

                        ReceivedTextFile?.Invoke(filesList[filesList.Count - 1]);

                        STATUS_RESPONSE choice = await uploadFileObj.UserResponseTcs.Task;

                        if (choice == STATUS_RESPONSE.REJECT)
                        {
                            await SendRejectResponseAsync(outStream);
                            return;
                        }
                        else
                        {
                            await SendOkWithoutStreamResponseAsync(outStream, "application/json");
                            return;
                        }
                    }

                    tokenMap[id] = token;
                    _fileNames[id] = name;
                    responseFiles[id] = token;
                }

                _activeSessions[sessionId] = tokenMap;

                var respObj = new { sessionId = sessionId, files = responseFiles };
                string responseJson = JsonConvert.SerializeObject(respObj);
                await SendResponseAsync(outStream, "200 OK", "application/json", responseJson);
            }
            catch
            {
                await SendResponseAsync(outStream, "500 Internal Server Error", "application/json", "{}");
            }
        }

        private async Task HandleFileUploadAsync(string queryString, Stream bodyStream, bool isChunked, long contentLength, Stream outStream)
        {
            // 1. 防御性检查
            if (string.IsNullOrWhiteSpace(queryString) || queryString == "?")
            {
                await SendResponseAsync(outStream, "400 Bad Request", "text/plain", "Missing query parameters");
                return;
            }

            // 2. 解析 QueryString
            string sessionId = null, fileId = null, token = null;
            try
            {
                var decoder = new Windows.Foundation.WwwFormUrlDecoder(queryString);
                foreach (var entry in decoder)
                {
                    if (entry.Name.Equals("sessionId", StringComparison.OrdinalIgnoreCase)) sessionId = entry.Value;
                    else if (entry.Name.Equals("fileId", StringComparison.OrdinalIgnoreCase)) fileId = entry.Value;
                    else if (entry.Name.Equals("token", StringComparison.OrdinalIgnoreCase)) token = entry.Value;
                }
            }
            catch
            {
                await SendResponseAsync(outStream, "400 Bad Request", "text/plain", "Invalid query");
                return;
            }

            if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(fileId) || string.IsNullOrEmpty(token))
            {
                await SendResponseAsync(outStream, "400 Bad Request", "text/plain", "Incomplete parameters");
                return;
            }

            // 3. 校验 Token
            if (!_activeSessions.TryGetValue(sessionId, out var files) ||
                !files.TryGetValue(fileId, out var expectedToken) ||
                expectedToken != token)
            {
                await SendResponseAsync(outStream, "403 Forbidden", "text/plain", "Invalid Token");
                return;
            }

            string fileName = _fileNames.TryGetValue(fileId, out var name) ? name : "received_file.bin";
            string ext = Path.GetExtension(fileName);

            if (ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            // 4. 使用 TaskCompletionSource 让后台线程等待 UI 弹窗选择彻底结束
            var tcs = new TaskCompletionSource<StorageFile>();

            var dispatcher = Windows.ApplicationModel.Core.CoreApplication.MainView.CoreWindow.Dispatcher;
            await dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, async () =>
            {
                try
                {
                    var savePicker = new FileSavePicker();
                    savePicker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.Downloads;
                    savePicker.SuggestedFileName = Path.GetFileNameWithoutExtension(fileName);

                    if (string.IsNullOrEmpty(ext))
                    {
                        ext = ".bin";
                    }
                    savePicker.FileTypeChoices.Add("文件类型", new System.Collections.Generic.List<string>() { ext });

                    var pickedFile = await savePicker.PickSaveFileAsync();
                    tcs.TrySetResult(pickedFile);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[Picker 异常] {ex.Message}");
                    tcs.TrySetResult(null);
                }
            });

            StorageFile file = await tcs.Task;

            // 5. 判断用户是否选择了保存位置
            if (file == null)
            {
                // 用户取消：排空网络流以保持连接正常闭合
                if (isChunked)
                {
                    await ReadOrDiscardChunkedStreamAsync(bodyStream, null);
                }
                else
                {
                    byte[] discardBuf = new byte[8192];
                    long remainingDiscard = contentLength;
                    while (remainingDiscard > 0)
                    {
                        int r = await bodyStream.ReadAsync(discardBuf, 0, (int)Math.Min(discardBuf.Length, remainingDiscard));
                        if (r == 0) break;
                        remainingDiscard -= r;
                    }
                }

                await SendResponseAsync(outStream, "409 Conflict", "text/plain", "User cancelled save");
                return;
            }

            // 6. 写入用户选定的目标文件
            using (var destStream = await file.OpenStreamForWriteAsync())
            {
                if (isChunked)
                {
                    // Chunked 模式：逐块解析十六进制长度并直接写入目标文件
                    await ReadOrDiscardChunkedStreamAsync(bodyStream, destStream);
                }
                else
                {
                    // 定长模式：根据 Content-Length 计数递减写入
                    byte[] buffer = new byte[65536];
                    long remaining = contentLength;
                    while (remaining > 0)
                    {
                        int read = await bodyStream.ReadAsync(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                        if (read == 0) break;
                        await destStream.WriteAsync(buffer, 0, read);
                        remaining -= read;
                    }
                }
            }

            // 7. 清理 Token 并通知传输完成
            files.TryRemove(fileId, out _);
            await SendResponseAsync(outStream, "200 OK", "application/json", "{}");
        }

        /// <summary>
        /// 解析 HTTP Chunked 字节流。如果 destStream 为 null，则仅排空网络流不写入文件。
        /// </summary>
        private async Task ReadOrDiscardChunkedStreamAsync(Stream inStream, Stream destStream)
        {
            byte[] buffer = new byte[65536];

            while (true)
            {
                // 1. 读取十六进制 Chunk 块长度（直到 \r\n）
                string sizeLine = await ReadLineAsciiAsync(inStream);
                if (string.IsNullOrEmpty(sizeLine))
                {
                    break;
                }

                int extIndex = sizeLine.IndexOf(';');
                if (extIndex >= 0)
                {
                    sizeLine = sizeLine.Substring(0, extIndex);
                }

                long chunkSize = Convert.ToInt64(sizeLine.Trim(), 16);

                // 2. 长度为 0 表示 Chunk 结束块
                if (chunkSize == 0)
                {
                    // 吸收终止块尾部的空行 \r\n
                    await ReadLineAsciiAsync(inStream);
                    break;
                }

                // 3. 读取当前 Chunk 块的真实字节并写入或丢弃
                long remaining = chunkSize;
                while (remaining > 0)
                {
                    int toRead = (int)Math.Min(buffer.Length, remaining);
                    int read = await inStream.ReadAsync(buffer, 0, toRead);
                    if (read == 0)
                    {
                        throw new EndOfStreamException("网络连接异常断开，Chunk 数据不完整");
                    }

                    if (destStream != null)
                    {
                        await destStream.WriteAsync(buffer, 0, read);
                    }
                    remaining -= read;
                }

                // 4. 吸收并丢弃每个 Chunk 块末尾固定的 \r\n 两个字节
                byte[] crlf = new byte[2];
                int crlfRead = 0;
                while (crlfRead < 2)
                {
                    int r = await inStream.ReadAsync(crlf, crlfRead, 2 - crlfRead);
                    if (r == 0) break;
                    crlfRead += r;
                }
            }
        }

        /// <summary>
        /// 从 Stream 读取单行 ASCII 文本（直到遇到 \r\n）
        /// </summary>
        private async Task<string> ReadLineAsciiAsync(Stream stream)
        {
            var bytes = new System.Collections.Generic.List<byte>();
            byte[] single = new byte[1];

            while (true)
            {
                int r = await stream.ReadAsync(single, 0, 1);
                if (r == 0) break;

                bytes.Add(single[0]);
                int count = bytes.Count;
                if (count >= 2 && bytes[count - 2] == '\r' && bytes[count - 1] == '\n')
                {
                    return Encoding.ASCII.GetString(bytes.ToArray(), 0, count - 2);
                }

                if (count > 256) throw new InvalidDataException("Chunk 长度头超长异常");
            }

            return bytes.Count > 0 ? Encoding.ASCII.GetString(bytes.ToArray()) : null;
        }

        /// <summary>
        /// 严格按照 Content-Length 字节数从原生 Stream 读取，不受字符编码长度差和 StreamReader 缓冲区的任何影响
        /// </summary>
        private async Task<string> ReadExactBytesAsStringAsync(Stream stream, long length, int timeoutMs = 5000)
        {
            if (length <= 0) return string.Empty;
            if (length > 2 * 1024 * 1024) return null; // 超过 2MB 拒绝

            byte[] buffer = new byte[length];
            int totalRead = 0;

            using (var cts = new CancellationTokenSource(timeoutMs))
            {
                while (totalRead < length)
                {
                    // 每次读满剩余所需的字节数
                    int toRead = (int)(length - totalRead);
                    int read = await stream.ReadAsync(buffer, totalRead, toRead);

                    // 如果对端断开，立刻跳出
                    if (read == 0) break;

                    totalRead += read;
                }
            }

            if (totalRead == 0) return null;
            return Encoding.UTF8.GetString(buffer, 0, totalRead);
        }

        private async Task SendResponseAsync(Stream outStream, string status, string contentType, string content)
        {
            byte[] body = Encoding.UTF8.GetBytes(content);
            string header = $"HTTP/1.1 {status}\r\n" +
                            $"Content-Type: {contentType}\r\n" +
                            $"Content-Length: {body.Length}\r\n" +
                            "Connection: close\r\n\r\n";
            byte[] headerBytes = Encoding.UTF8.GetBytes(header);
            await outStream.WriteAsync(headerBytes, 0, headerBytes.Length);
            if (body.Length > 0)
            {
                await outStream.WriteAsync(body, 0, body.Length);
            }
            await outStream.FlushAsync();
        }

        public async Task SendPlainTextAsync(string targetIp, string text, int targetPort = 53317)
        {
            var file = new List<PreUploadFile>();
            file.Add(PreUploadFile.PreUploadTextFile(text));
            await SendPrepaidUploadFileAsync(targetIp, file, targetPort);
        }

        public async Task SendPrepaidUploadFileAsync(string targetIp, List<PreUploadFile> preUploadFiles, int targetPort = 53317, string protocol = "https")
        {

            var filter = new HttpBaseProtocolFilter();
            // 关键：在 10586 下对自签名证书必须加入所有可能的链错误忽略
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.WrongUsage);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.RevocationFailure);
            /*var clientCert = await GetOrCreateClientCertificateAsync();
            if (clientCert != null)
            {
                filter.ClientCertificate = clientCert;
            }*/
            var clientCert = await LocalSendSecurityManager.GetOrCreateClientCertificateAsync();
            if (clientCert != null)
            {
                filter.ClientCertificate = clientCert;
            }

            // 4. 获取与证书严格吻合的 SHA-256 指纹
            string fingerprint = await LocalSendSecurityManager.GetFingerprintAsync();

            try
            {

                using (var client = new HttpClient(filter))
                {

                    var payload = new
                    {
                        info = new
                        {
                            alias = DeviceAlias,
                            version = "2.0",
                            deviceModel = "Windows",
                            deviceType = "desktop",
                            fingerprint = fingerprint,
                            port = 53317,
                            protocol = "http",
                            download = false
                        },
                        files = new Dictionary<string, PreUploadFile>()
                    };

                    foreach (var file in preUploadFiles)
                    {
                        payload.files.Add(file.Id, file);
                    }

                    string jsonReq = JsonConvert.SerializeObject(payload);
                    var content = new HttpStringContent(
                        jsonReq,
                        Windows.Storage.Streams.UnicodeEncoding.Utf8,
                        "application/json");

                    var uri = new Uri($"{protocol}://{targetIp}:{targetPort}/api/localsend/v2/prepare-upload");

                    var response = await client.PostAsync(uri, content);

                    if (response.IsSuccessStatusCode)
                    {
                        string responseBody = await response.Content.ReadAsStringAsync();
                        UploadFilesRequestList uploadFiles = JsonConvert.DeserializeObject<UploadFilesRequestList>(responseBody);
                        bool useTls = protocol.Equals("https");

                        // 3. 循环发送已就绪的文件
                        var pendingDict = preUploadFiles.ToDictionary(f => f.Id, f => f);

                        // 2. 遍历对面同意接收并返回了 Token 的文件清单
                        foreach (var fileItem in uploadFiles.Files)
                        {
                            string fileId = fileItem.Key;      // 对应的就是 PreUploadFile.Id
                            string token = fileItem.Value;     // 对端分配的上传凭证

                            // 根据 Id 找到我们本地对应的 PreUploadFile 对象
                            if (!pendingDict.TryGetValue(fileId, out PreUploadFile preFile))
                            {
                                // 容错：如果对端返回的 id 本地没有，跳过
                                continue;
                            }

                            Stream streamToSend = preFile.stream;

                            // 重点避坑：如果 stream 是 MemoryStream 或可寻址流，必须将读取指针移到开头
                            if (streamToSend != null && streamToSend.CanSeek)
                            {
                                streamToSend.Position = 0;
                            }

                            // 执行上传
                            bool success = await SendUploadFileAsync(
                                ip: targetIp,
                                port: targetPort,
                                isHttps: useTls,
                                sessionId: uploadFiles.SessionId,
                                fileId: preFile.Id,
                                fileToken: token,
                                fileStream: streamToSend
                            );

                            if (!success)
                            {
                                // 发送失败处理逻辑
                                System.Diagnostics.Debug.WriteLine($"文件发送失败: {preFile.Name}");
                                break;
                            }
                            else
                            {
                                System.Diagnostics.Debug.WriteLine($"文件发送成功: {preFile.Name}");
                            }
                        }
                        return;

                    }
                    else if (response.StatusCode == HttpStatusCode.NoContent)
                    {
                        return;
                    }
                    else if (response.StatusCode == HttpStatusCode.Forbidden)
                    {

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
        }

        /// <summary>
        /// 向对端发送单个文件
        /// </summary>
        /// <param name="ip">对端 IP 地址</param>
        /// <param name="port">对端端口号（通常为 53317）</param>
        /// <param name="isHttps">是否使用 TLS (HTTPS)</param>
        /// <param name="sessionId">prepare-upload 返回的 sessionId</param>
        /// <param name="fileId">文件的唯一标识（prepare-upload 时的 key）</param>
        /// <param name="fileToken">对端分配的文件 Token（uploadFiles.Files[fileId] 的 value）</param>
        /// <param name="fileStream">待发送文件的流（支持 FileStream 或 StorageFile 打开的流）</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>是否传输成功</returns>
        public async Task<bool> SendUploadFileAsync(
            string ip,
            int port,
            bool isHttps,
            string sessionId,
            string fileId,
            string fileToken,
            Stream fileStream,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var filter = new HttpBaseProtocolFilter();
            // 关键：在 10586 下对自签名证书必须加入所有可能的链错误忽略
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.WrongUsage);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.RevocationFailure);
            /*var clientCert = await GetOrCreateClientCertificateAsync();
            if (clientCert != null)
            {
                filter.ClientCertificate = clientCert;
            }*/
            var clientCert = await LocalSendSecurityManager.GetOrCreateClientCertificateAsync();
            if (clientCert != null)
            {
                filter.ClientCertificate = clientCert;
            }
            using (var client = new HttpClient(filter))
            {
                // 1. 判断协议头是 http 还是 https
                string scheme = isHttps ? "https" : "http";

                // 2. 拼接 LocalSend v2 upload 接口 URL 与 Query 参数
                // LocalSend 规范：/api/localsend/v2/upload?sessionId={sessionId}&fileId={fileId}&token={token}
                string url = $"{scheme}://{ip}:{port}/api/localsend/v2/upload" +
                             $"?sessionId={Uri.EscapeDataString(sessionId)}" +
                             $"&fileId={Uri.EscapeDataString(fileId)}" +
                             $"&token={Uri.EscapeDataString(fileToken)}";

                try
                {
                    IInputStream winrtStream = fileStream.AsInputStream();
                    // 3. 构建二进制流 Payload（避免全部载入内存，适合移动端）
                    using (var content = new HttpStreamContent(winrtStream))
                    {
                        content.Headers.ContentType = new HttpMediaTypeHeaderValue("application/octet-stream");

                        // 4. 发起 POST 上传请求
                        using (var response = await client.PostAsync(new Uri(url), content).AsTask(cancellationToken))
                        {
                            if (response.IsSuccessStatusCode)
                            {
                                return true;
                            }

                            string errorBody = await response.Content.ReadAsStringAsync();
                            System.Diagnostics.Debug.WriteLine($"Upload failed [{response.StatusCode}]: {errorBody}");
                            return false;
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Exception during SendUploadFileAsync: {ex.Message}");
                    throw;
                }
            }
        }

        /* public async void SendResponse(Stream outStream, STATUS_RESPONSE status, string text = "")
         {
             switch (status)
             {
                 case STATUS_RESPONSE.OK:
                     await SendResponseAsync(outStream, "200 OK", "application/json", "{}");
                     break;
                 case STATUS_RESPONSE.INVALID:

             }
             return;

         }*/
        public async Task SendOkResponseAsync(Stream outStream, string contentType, string text = "{}")
        {
            await SendResponseAsync(outStream, "200 OK", contentType, text);
            return;
        }
        public async Task SendOkWithoutStreamResponseAsync(Stream outStream, string contentType, string text = "{}")
        {
            await SendResponseAsync(outStream, "204 OK", contentType, text);
            return;
        }
        public async Task SendRejectResponseAsync(Stream outStream)
        {
            await SendResponseAsync(outStream, "403 Forbidden", "text/plain", "User cancelled save");
            return;
        }


        private static Certificate _cachedCertificate;

        /*private async Task<Certificate> GetOrCreateClientCertificateAsync()
        {
            if (_cachedCertificate != null)
            {
                return _cachedCertificate;
            }

            string certSubject = "CN=UniSendClient";

            // 优先从应用个人证书存储区寻找已存在的证书
            var query = new CertificateQuery();
            query.IssuerName = certSubject;
            var certs = await CertificateStores.FindAllAsync(query);

            if (certs.Count > 0)
            {
                _cachedCertificate = certs[0];
                return _cachedCertificate;
            }

            // 没有则动态创建一个自签名证书
            var req = new CertificateRequestProperties
            {
                Subject = certSubject,
                KeyAlgorithmName = KeyAlgorithmNames.Rsa,
                KeySize = 2048,
                FriendlyName = "UniSend LocalSend TLS Cert"
            };

            // 生成自签名证书并存入证书库
            _cachedCertificate = await CertificateEnrollmentManager.CreateSelfSignedCertificateAsync(
                req,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddYears(5));

            return _cachedCertificate;
        }*/

        public void Dispose() => _listener?.Dispose();
    }

    public enum STATUS_RESPONSE
    {
        OK,
        OK_WITHOUT_RECEIVE,
        INVALID,
        REJECT,
        UNKNOWN
    }

    public class WebResponse
    {
        public HttpStatusCode Code { get; set; }
        public string Message { get; set; }
    }
}