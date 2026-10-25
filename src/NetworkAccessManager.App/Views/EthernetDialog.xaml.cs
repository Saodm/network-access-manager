using System.Windows;
using NetworkAccessManager.Core.Network;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.App.Views;

public partial class EthernetDialog : Window
{
    private readonly bool _disable;

    public EthernetDialog(
        bool disable,
        IReadOnlyList<EthernetAdapterInfo> adapters,
        IReadOnlyList<EthernetAdapterRecord> records)
    {
        InitializeComponent();
        _disable = disable;
        Title = disable ? "禁用以太网" : "恢复以太网";
        HeaderText.Text = disable ? "禁用以太网" : "恢复以太网";
        SubtitleText.Text = disable
            ? "接下来会禁用本机所有当前启用的物理以太网适配器。这是对网卡的管理状态修改，不是只拦截某个进程。"
            : "只重新启用本工具记录为已禁用的以太网适配器；不会改动你手动禁用的其他设备。";

        if (disable)
        {
            WarningText.Text =
                "禁用后本机以太网会立即中断。若你正在使用远程桌面、远程协助或通过网络访问本机，将无法远程恢复；必须在本机操作。恢复入口会保留在主界面和系统托盘。";
            AdapterGrid.ItemsSource = adapters
                .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
                .Select(a => new AdapterRow(a.Name, a.Description, a.StatusText))
                .ToList();
            FooterText.Text = "确认后会通过管理员授权禁用网络。程序不会退出，而是继续留在系统托盘。";
            ConfirmButton.Content = "确认禁用网络";
            ConfirmButton.IsEnabled = false;
        }
        else
        {
            WarningPanel.Visibility = Visibility.Collapsed;
            AdapterGrid.ItemsSource = records
                .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
                .Select(a => new AdapterRow(a.Name, a.Description, "由本工具禁用"))
                .ToList();
            FooterText.Text = "恢复操作需要管理员授权；若部分适配器已被外部删除或改回启用，界面会显示实际结果。";
            ConfirmButton.Content = "恢复网络";
            ConfirmButton.IsEnabled = true;
        }
    }

    private void Ack_Changed(object sender, RoutedEventArgs e)
    {
        if (_disable)
            ConfirmButton.IsEnabled = AckCheck.IsChecked == true;
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (_disable && AckCheck.IsChecked != true) return;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private sealed record AdapterRow(string Name, string Description, string StatusText);
}
