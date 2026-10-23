using System.Windows;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.Views;

public partial class NetworkTargetDialog : Window
{
    private NetworkTargetValidationResult? _validation;
    private BlockDirections _directions = BlockDirections.Outbound;
    private bool _initialized;

    public NetworkTargetDialog(bool firewallReadable, string? firewallStatus)
    {
        InitializeComponent();
        FirewallPanel.Visibility = firewallReadable ? Visibility.Collapsed : Visibility.Visible;
        FirewallText.Text = firewallReadable
            ? string.Empty
            : "当前界面无法确认 Windows 防火墙状态（可能因为普通权限无法读取规则）。仍可继续；管理员辅助进程会在创建前重新检查。如果防火墙服务实际不可用或当前配置文件未启用，操作会被拒绝，不会声称成功。";
        _initialized = true;
        RefreshState();
    }

    public string? SelectedTarget { get; private set; }
    public BlockDirections SelectedDirections { get; private set; } = BlockDirections.Outbound;

    public static string? ValidateForDialog(string? text, out NetworkTargetValidationResult? result)
    {
        result = NetworkTargetValidator.Validate(text);
        return result.IsValid ? null : result.Error;
    }

    private void Target_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (!_initialized) return;
        _validation = NetworkTargetValidator.Validate(TargetTextBox.Text);
        RefreshState();
    }

    private void Direction_Checked(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        _directions = BothRadio.IsChecked == true ? BlockDirections.Both :
            InboundRadio.IsChecked == true ? BlockDirections.Inbound : BlockDirections.Outbound;
        RefreshState();
    }

    private void Ack_Changed(object sender, RoutedEventArgs e)
    {
        if (_initialized) RefreshState();
    }

    private void RefreshState()
    {
        if (!IsLoaded && _validation is null && string.IsNullOrWhiteSpace(TargetTextBox.Text))
        {
            ValidationText.Text = string.Empty;
            NormalizedText.Text = string.Empty;
            SummaryText.Text = string.Empty;
            ConfirmButton.IsEnabled = false;
            return;
        }

        _validation ??= NetworkTargetValidator.Validate(TargetTextBox.Text);
        var valid = _validation.IsValid;
        ValidationText.Text = valid ? string.Empty : _validation.Error ?? string.Empty;
        ValidationText.Visibility = valid ? Visibility.Collapsed : Visibility.Visible;
        NormalizedText.Text = valid ? $"将阻断：{_validation.NormalizedTarget}" : string.Empty;
        var risky = valid && (_validation.IsBroadScope || _validation.IsLoopback || _validation.IsMulticast);
        RiskPanel.Visibility = risky ? Visibility.Visible : Visibility.Collapsed;
        RiskText.Text = risky ? _validation.Warning ?? "该目标可能影响大量网络访问或本机通信。" : string.Empty;
        if (!risky) HighRiskAckCheckBox.IsChecked = false;
        SummaryText.Text = valid
            ? $"方向：{_directions.ToChinese()}。该目标会影响所有访问此地址范围的应用程序。"
            : "输入合法地址后才会启用创建按钮。";
        ConfirmButton.IsEnabled = valid && (!risky || HighRiskAckCheckBox.IsChecked == true);
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        _validation = NetworkTargetValidator.Validate(TargetTextBox.Text);
        if (_validation is not { IsValid: true }) return;
        var risky = _validation.IsBroadScope || _validation.IsLoopback || _validation.IsMulticast;
        if (risky && HighRiskAckCheckBox.IsChecked != true) return;
        SelectedTarget = _validation.NormalizedTarget;
        SelectedDirections = _directions;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
