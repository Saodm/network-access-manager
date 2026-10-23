using System.Windows;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.Views;

public partial class BlockDialog : Window
{
    private readonly IReadOnlyList<UiTargetOption> _programTargets;
    private readonly IReadOnlyList<UiTargetOption> _networkTargets;
    private readonly bool _allowKindChoice;
    private bool _initialized;

    public BlockDialog(
        IReadOnlyList<UiTargetOption> programTargets,
        IReadOnlyList<UiTargetOption> networkTargets,
        bool allowKindChoice = false,
        RuleTargetKind initialKind = RuleTargetKind.Program)
    {
        InitializeComponent();
        _programTargets = programTargets;
        _networkTargets = networkTargets;
        _allowKindChoice = allowKindChoice;

        ModePanel.Visibility = allowKindChoice ? Visibility.Visible : Visibility.Collapsed;
        var useNetwork = initialKind == RuleTargetKind.NetworkAddress ||
                         programTargets.All(t => !t.CanBlock) && networkTargets.Any(t => t.CanBlock);
        ProgramModeRadio.IsChecked = !useNetwork;
        NetworkModeRadio.IsChecked = useNetwork;
        OutboundRadio.IsChecked = true;
        _initialized = true;
        SelectedKind = useNetwork ? RuleTargetKind.NetworkAddress : RuleTargetKind.Program;
        if (!allowKindChoice)
            ModePanel.Visibility = Visibility.Collapsed;
        RefreshDisplay();
    }

    public RuleTargetKind SelectedKind { get; private set; } = RuleTargetKind.Program;
    public BlockDirections SelectedDirections { get; private set; } = BlockDirections.Outbound;
    public IReadOnlyList<UiTargetOption> SelectedTargets { get; private set; } = Array.Empty<UiTargetOption>();
    public bool Confirmed { get; private set; }

    private void TargetMode_Checked(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        SelectedKind = NetworkModeRadio.IsChecked == true ? RuleTargetKind.NetworkAddress : RuleTargetKind.Program;
        RefreshDisplay();
    }

    private void Direction_Checked(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        SelectedDirections = BothRadio.IsChecked == true
            ? BlockDirections.Both
            : InboundRadio.IsChecked == true ? BlockDirections.Inbound : BlockDirections.Outbound;
        RefreshDisplay();
    }

    private void Ack_Changed(object sender, RoutedEventArgs e)
    {
        if (_initialized) UpdateConfirmState();
    }

    private void RefreshDisplay()
    {
        if (!_initialized) return;
        var options = SelectedKind == RuleTargetKind.Program ? _programTargets : _networkTargets;
        TargetGrid.ItemsSource = options;
        EmptyTargetsText.Visibility = options.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var eligible = options.Where(o => o.CanBlock).ToList();
        SelectedTargets = eligible;
        var ineligible = options.Count - eligible.Count;
        var directionText = SelectedDirections.ToChinese();
        ListSummaryText.Text = $"将应用 {eligible.Count} 项" + (ineligible > 0 ? $" · 跳过 {ineligible} 项" : string.Empty);
        SelectionSummaryText.Text = eligible.Count == 0
            ? "当前方式没有可执行对象。"
            : $"将创建 {eligible.Count} 项规则 · {directionText}";
        EffectText.Text = $"将通过 Windows 防火墙创建阻断规则，方向：{directionText}。规则创建后会核对实际属性；只有验证通过才会记录为已生效。";
        ScopeText.Text = SelectedKind == RuleTargetKind.Program
            ? "规则按可执行文件路径作用于本机所有该程序的实例及所有用户。不是只阻断选中的 PID。"
            : "规则按远程地址范围作用于所有访问该地址范围的应用程序，不限制端口，也不只影响当前进程。";
        HeaderHint.Text = SelectedKind == RuleTargetKind.Program
            ? "请核对程序完整路径、方向和影响范围。确认后将通过标准 Windows UAC 请求管理员授权。"
            : "请核对远程地址范围和作用方向。目标规则会影响多个应用。确认后将通过标准 Windows UAC 请求管理员授权。";

        var needsAck = eligible.Any(o => o.RequiresHighRiskAck || o.Risk >= RiskLevel.High || o.IsNetworkBroad);
        RiskPanel.Visibility = needsAck ? Visibility.Visible : Visibility.Collapsed;
        HighRiskAckCheckBox.IsChecked = false;
        HighRiskAckCheckBox.Visibility = needsAck ? Visibility.Visible : Visibility.Collapsed;
        RiskText.Text = needsAck
            ? "所选对象包含系统/服务进程、范围较大的网络地址或本机回环/组播地址。阻断可能导致系统功能、设备发现或本机程序通信异常。请确认确实需要继续。"
            : string.Empty;
        UpdateConfirmState();
    }

    private void UpdateConfirmState()
    {
        var needsAck = RiskPanel.Visibility == Visibility.Visible;
        ConfirmButton.IsEnabled = SelectedTargets.Count > 0 && (!needsAck || HighRiskAckCheckBox.IsChecked == true);
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedTargets.Count == 0) return;
        if (RiskPanel.Visibility == Visibility.Visible && HighRiskAckCheckBox.IsChecked != true) return;
        Confirmed = true;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Confirmed = false;
        DialogResult = false;
    }
}
