using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
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
using Windows.UI.Popups;
using Windows.ApplicationModel.DataTransfer.ShareTarget;

namespace UniSend
{
    public sealed partial class MainPage : Page
    {

        private ShareOperation _shareOperation;

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

            string fingerprint = DeviceIdentityHelper.GetFingerprint();

            var deviceInfo = new EasClientDeviceInformation();

            string alias = deviceInfo.FriendlyName + " UWP";

            _httpServer = new LocalSendHttpServer
            {
                DeviceAlias = alias,
                Fingerprint = fingerprint
            };
            _httpServer.DeviceDiscovered += OnDeviceFound;
            _httpServer.ReceivedTextFile += ReceivedTextFile;
            _httpServer.SetProgressRingStatus += SetProgressRingStatus;
            await _httpServer.StartAsync(fingerprint);

            _discoveryService = new LocalSendDiscoveryService
            {
                DeviceAlias = alias,
                Fingerprint = fingerprint
            };
            _discoveryService.DeviceDiscovered += OnDeviceFound;
            await _discoveryService.StartAsync(fingerprint);
        }

        protected override async void OnNavigatedTo(Windows.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            if (e.Parameter is ShareOperation shareOp)
            {
                FileChooseButtonsPanel.Visibility = Visibility.Collapsed;
                _shareOperation = e.Parameter as ShareOperation;
                if (_shareOperation == null) return;

                // 通知系统正在处理
                _shareOperation.ReportStarted();

                try
                {
                    var dataView = _shareOperation.Data;

                    // 1. 如果分享的是纯文本
                    if (dataView.Contains(StandardDataFormats.Text))
                    {
                        preUploadFiles.Add(PreUploadFile.PreUploadTextFile(await dataView.GetTextAsync()));
                        FileItems.Add(new CardItem
                        {
                            Title = "",
                            Icon = "\uEA37"
                        });
                    }

                    // 2. 如果分享的是文件（如相册选中的照片）
                    if (dataView.Contains(StandardDataFormats.StorageItems))
                    {
                        IReadOnlyList<IStorageItem> items = await dataView.GetStorageItemsAsync();
                        foreach (var item in items)
                        {
                            StorageFile file = item as StorageFile;
                            if (file != null)
                            {
                                preUploadFiles.Add(new PreUploadFile
                                {
                                    Id = Guid.NewGuid().ToString(),
                                    Name = file.Name,
                                    fileType = file.ContentType,
                                    Size = (long)(await file.GetBasicPropertiesAsync()).Size,
                                    stream = await file.OpenStreamForReadAsync()
                                });
                                FileItems.Add(new CardItem
                                {
                                    Title = file.Name,
                                    Icon = "\uE8E5"
                                });
                            }
                        }
                    }

                    // 处理完成后必须通知系统关闭面板
                    
                }
                catch
                {
                    _shareOperation.ReportError("处理分享内容时出错");
                }
               
            }

            
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
            SetProgressRingStatus(true);
            var target = (DeviceDto)e.ClickedItem;
            await _httpServer.SendPrepaidUploadFileAsync(target.Ip, preUploadFiles, target.Port, target.Protocol);
            await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, async () =>
            {
                try
                {
                    await new MessageDialog("已发送" + preUploadFiles.Count + "个文件").ShowAsync();

                }
                catch (Exception ex)
                {

                }
            });
            preUploadFiles.Clear();
            FileItems.Clear();
            SetProgressRingStatus(false);
            if (_shareOperation != null)
            {
                _shareOperation.ReportCompleted();
                _shareOperation = null;
            }
        }

        private async void ChooseFileButton_Click(object sender, RoutedEventArgs e)
        {

            var picker = new Windows.Storage.Pickers.FileOpenPicker();
            picker.ViewMode = Windows.Storage.Pickers.PickerViewMode.Thumbnail;
            picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.DocumentsLibrary;
            picker.FileTypeFilter.Add("*");

            IReadOnlyCollection<StorageFile> filesList = await picker.PickMultipleFilesAsync();

            foreach (var file in filesList)
            {
                if (file != null)
                {
                    preUploadFiles.Add(new PreUploadFile
                    {
                        Id = Guid.NewGuid().ToString(),
                        Name = file.Name,
                        fileType = file.ContentType,
                        Size = (long)(await file.GetBasicPropertiesAsync()).Size,
                        stream = await file.OpenStreamForReadAsync()
                    });
                    FileItems.Add(new CardItem
                    {
                        Title = file.Name,
                        Icon = "\uE8E5"
                    });
                }
            }


        }

        private async void ChoosePhotoButton_Click(object sender, RoutedEventArgs e)
        {
            var picker = new Windows.Storage.Pickers.FileOpenPicker();
            picker.ViewMode = Windows.Storage.Pickers.PickerViewMode.Thumbnail;
            picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.PicturesLibrary;
            picker.FileTypeFilter.Add(".jpg");
            picker.FileTypeFilter.Add(".jpeg");
            picker.FileTypeFilter.Add(".png");
            picker.FileTypeFilter.Add(".gif");
            picker.FileTypeFilter.Add(".heic");


            IReadOnlyCollection<StorageFile> filesList = await picker.PickMultipleFilesAsync();
            foreach (var file in filesList)
            {
                if (file != null)
                {
                    preUploadFiles.Add(new PreUploadFile
                    {
                        Id = Guid.NewGuid().ToString(),
                        Name = file.Name,
                        fileType = file.ContentType,
                        Size = (long)(await file.GetBasicPropertiesAsync()).Size,
                        stream = await file.OpenStreamForReadAsync()
                    });
                    FileItems.Add(new CardItem
                    {
                        Title = file.Name,
                        Icon = "\uE8E5"
                    });
                }
            }
        }

        public async void SetProgressRingStatus(bool isEnable)
        {
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () => {
                SendProgressRing.IsActive = isEnable;
                RootGrid.IsHitTestVisible = !isEnable;
            });
            
        }
    }
}