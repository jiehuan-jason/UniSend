namespace UniSend.Models
{
    public class DeviceDto
    {
        public string Ip { get; set; } = "";
        public int Port { get; set; }
        public string Alias { get; set; }
        public string DeviceModel { get; set; }
        public string DeviceType { get; set; }
        public string Fingerprint { get; set; }
        public string Protocol { get; set; }
        public string Version { get; set; } = "2.0";

        public string DisplayText => $"{Alias} ({Ip}:{Port}) [{DeviceModel ?? DeviceType}]";
    }
}