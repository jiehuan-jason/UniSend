using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UniSend.Services;
using Windows.UI.Xaml.Controls;

namespace UniSend.Models
{
    public class ReceivedUploadFile : FileModel
    {
        public string Token { get; set; }
        
        public string SenderName { get; set; }
        public Stream stream { get; set; }
        public TaskCompletionSource<STATUS_RESPONSE> UserResponseTcs { get; }
        = new TaskCompletionSource<STATUS_RESPONSE>();
    }
    public class FileModel
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("fileName")]
        public string Name { get; set; }

        [JsonProperty("fileType")]
        public string fileType { get; set; }

        [JsonProperty("preview")]
        public string Preview { get; set; } = "";
    }

    public class PreUploadFile : FileModel
    {
        [JsonProperty("size")]
        public long Size { get; set; }

        public PreUploadFile() { }

        static public PreUploadFile PreUploadTextFile(string text)
        {
            var obj = new PreUploadFile();
            obj.Id = Guid.NewGuid().ToString();
            obj.Name = obj.Id + ".txt";
            obj.fileType = "text/plain";
            obj.Size = Encoding.UTF8.GetByteCount(text);
            obj.Preview = text;
            return obj;
        }
    }

    public class UploadFilesRequestList
    {
        public string SessionId { get; set; }
        public Dictionary<string, string> Files { get; set; } = new Dictionary<string, string>();

        
    }

    public class CardItem
    {
        public string Title { get; set; }
        public string Icon { get; set; } // 内置图标，比如 Symbol.Document, Symbol.Camera
    }
}
