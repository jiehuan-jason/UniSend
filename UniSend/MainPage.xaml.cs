using System;
using System.Collections.ObjectModel;
using System.Linq;
using Windows.Storage;
using Windows.System;
using Windows.UI.Core;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using UniSend.Models;
using UniSend.Services;
using Windows.Devices.Enumeration;
using Windows.Security.ExchangeActiveSyncProvisioning;
using Windows.ApplicationModel.DataTransfer;
using UniSend.Dialogs;
using System.Collections.Generic;

namespace UniSend
{
    public sealed partial class MainPage : Page
    {
        private LocalSendHttpServer _httpServer;
        private LocalSendDiscoveryService _discoveryService;

        // 绑定的设备集合
        public ObservableCollection<DeviceDto> DiscoveredDevices { get; } = new ObservableCollection<DeviceDto>();
        public ObservableCollection<CardItem> FileItems { get; } = new ObservableCollection<CardItem>();
        public List<PreUploadFile> preUploadFiles = new List<PreUploadFile>();

        public event Action<string, DeviceDto> SendUploadResquest;
        

        public MainPage()
        {
            this.InitializeComponent();
            DeviceListView.ItemsSource = DiscoveredDevices;
            this.Loaded += MainPage_Loaded;
        }

        private async void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            SendUploadResquest += UploadTextFile;

            string fingerprint = DeviceIdentityHelper.GenerateFingerprint();

            var deviceInfo = new EasClientDeviceInformation();

            string alias = deviceInfo.FriendlyName + " UWP";

            _httpServer = new LocalSendHttpServer
            {
                DeviceAlias = alias,
                Fingerprint = fingerprint
            };
            _httpServer.DeviceDiscovered += OnDeviceFound;
            _httpServer.ReceivedTextFile += ReceivedTextFile;
            await _httpServer.StartAsync(fingerprint);

            _discoveryService = new LocalSendDiscoveryService
            {
                DeviceAlias = alias,
                Fingerprint = fingerprint
            };
            _discoveryService.DeviceDiscovered += OnDeviceFound;
            await _discoveryService.StartAsync(fingerprint);
        }

        private async void ReceivedTextFile(ReceivedUploadFile obj)
        {
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, async () =>
            {
                ContentDialog receivedTextDialog = new ContentDialog()
                {
                    Title = "Text sent from " + obj.SenderName,
                    Content = obj.Preview,
                    PrimaryButtonText = "Copy",
                    SecondaryButtonText = "Reject",
                    CloseButtonText = "OK",
                    DefaultButton = ContentDialogButton.Close
                };

                var result = await receivedTextDialog.ShowAsync();
                if (result == ContentDialogResult.Primary)
                {
                    setPasteBoradContent(obj.Preview);
                }

                if (result == ContentDialogResult.Secondary)
                {
                    obj.UserResponseTcs.TrySetResult(STATUS_RESPONSE.REJECT);

                }
                else
                {
                    obj.UserResponseTcs.TrySetResult(STATUS_RESPONSE.OK_WITHOUT_RECEIVE);
                }
            });

            AppendLog("[Receive] From "+ obj.SenderName + " : " + obj.Preview);
        }

        private void setPasteBoradContent(String content)
        {
            var dataPackage = new DataPackage();
            dataPackage.SetText(content);
            Clipboard.SetContent(dataPackage);
        }

        // 收到设备广播时更新到 ListView
        private async void OnDeviceDiscovered(DeviceDto device)
        {
            // 切回 UI 线程更新 ObservableCollection
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
            {
                // 根据指纹或 IP 去重更新
                var existing = DiscoveredDevices.FirstOrDefault(d => d.Fingerprint == device.Fingerprint || d.Ip == device.Ip);
                if (existing == null)
                {
                    DiscoveredDevices.Add(device);
                    AppendLog($"发现新设备: {device.Alias} ({device.Ip})");
                }
                else
                {
                    // 更新现有设备信息
                    existing.Alias = device.Alias;
                    existing.Port = device.Port;
                }
            });
        }

        private async void OnBroadcastClick(object sender, RoutedEventArgs e)
        {
            if (_discoveryService != null)
            {
                await _discoveryService.SendAnnouncementAsync(announce: true);
                AppendLog("已发送组播广播");
            }
        }

        private async void OnOpenFolderClick(object sender, RoutedEventArgs e)
        {
            await Launcher.LaunchFolderAsync(ApplicationData.Current.LocalFolder);
        }

        private async void OnDeviceFound(UniSend.Models.DeviceDto device)
        {
            // 切换回 UI 线程，避免跨线程异常
            await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
            {
                // 打印调试信息，验证发现的设备
                //System.Diagnostics.Debug.WriteLine($"[发现设备] 别名: {device.Alias}, IP: {device.Ip}:{device.Port}, 协议: {device.Protocol}");

                var existing = DiscoveredDevices.FirstOrDefault(d => d.Fingerprint == device.Fingerprint || d.Ip == device.Ip);
                if (existing == null)
                {
                    DiscoveredDevices.Add(device);
                    AppendLog($"发现新设备: {device.Alias} ({device.Ip})");
                }
                else
                {
                    // 更新现有设备信息
                    existing.Alias = device.Alias;
                    existing.Port = device.Port;
                }
                // TODO: 在这里把 device 添加到你的界面列表（例如 ObservableCollection<DeviceDto>）
            });
        }

        private async void AppendLog(string text)
        {
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
            {
                TxtLogs.Text += $"[{DateTime.Now:HH:mm:ss}] {text}\n";
            });
        }

        private async void ChooseTextButton_Click(object sender, RoutedEventArgs e)
        {
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, async () =>
            {
                InputContentDialog inputTextDialog = new InputContentDialog()
                {
                    Title = "Input Text",
                    PrimaryButtonText = "Cancel",
                    CloseButtonText = "OK",
                    DefaultButton = ContentDialogButton.Close
                };

                var result = await inputTextDialog.ShowAsync();
                if(result != ContentDialogResult.Primary)
                {
                    var text = inputTextDialog.inputTextBoxContent();
                    preUploadFiles.Add(PreUploadFile.PreUploadTextFile(text));
                    FileItems.Add(new CardItem
                    {
                        Title = "",
                        Icon = "\uEA37"
                    });
                }
            });
        }

        private async void UploadTextFile(string text, DeviceDto target)
        {
            await _httpServer.SendPlainTextAsync(target.Ip, text, target.Port);
        }

        private async void DeviceListView_ItemClick(object sender, ItemClickEventArgs e)
        {
            var target = (DeviceDto)e.ClickedItem;
            await _httpServer.SendPrepaidUploadFileAsync(target.Ip, preUploadFiles, target.Port, target.Protocol);
            preUploadFiles.Clear();
            FileItems.Clear();
        }
    }
}