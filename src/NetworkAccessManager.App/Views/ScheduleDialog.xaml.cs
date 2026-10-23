using System.Windows;
using System.Windows.Controls;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.Views;

public sealed class ScheduleTargetRow
{
    public required UiTargetOption Option { get; init; }
    public bool IsEligible { get; init; }
    public string EligibilityText { get; init; } = string.Empty;
    public string CurrentStateText { get; init; } = string.Empty;
    public string Display => Option.Display;
    public string Detail { get; init; } = string.Empty;
}

public partial class ScheduleDialog : Window
{
    private readonly IReadOnlyList<UiTargetOption> _programTargets;
    private readonly IReadOnlyList<UiTargetOption> _networkTargets;
    private bool _initialized;
    private ScheduledMode _mode = ScheduledMode.DelayedBlock;
    private RuleTargetKind _kind = RuleTargetKind.Program;
    private BlockDirections _directions = BlockDirections.Outbound;
    private int _minutes = 10;
    private bool _timeValid;

    public ScheduleDialog(
        IReadOnlyList<UiTargetOption> programTargets,
        IReadOnlyList<UiTargetOption> networkTargets,
        bool allowKindChoice,
        RuleTargetKind initialKind)
    {
        InitializeComponent();
        _programTargets = programTargets;
        _networkTargets = networkTargets;
        TypePanel.Visibility = allowKindChoice ? Visibility.Visible : Visibility.Collapsed;
        _kind = initialKind == RuleTargetKind.NetworkAddress && networkTargets.Count > 0
            ? RuleTargetKind.NetworkAddress
            : RuleTargetKind.Program;
        if (_kind == RuleTargetKind.NetworkAddress)
        {
            ProgramKindRadio.IsChecked = false;
            NetworkKindRadio.IsChecked = true;
        }
        else
        {
            ProgramKindRadio.IsChecked = true;
            NetworkKindRadio.IsChecked = false;
        }

        DelayedBlockRadio.IsChecked = true;
        OutboundRadio.IsChecked = true;
        MinutesTextBox.Text = "10";
        _initialized = true;
        RefreshAll(resetAck: true);
    }

    public ScheduledMode SelectedMode { get; private set; } = ScheduledMode.DelayedBlock;
    public RuleTargetKind SelectedKind { get; private set; } = RuleTargetKind.Program;
    public BlockDirections SelectedDirections { get; private set; } = BlockDirections.Outbound;
    public int SelectedMinutes { get; private set; }
    public IReadOnlyList<UiTargetOption> SelectedTargets { get; private set; } = Array.Empty<UiTargetOption>();

    private IReadOnlyList<UiTargetOption> CurrentOptions => _kind == RuleTargetKind.Program ? _programTargets : _networkTargets;

    private void Mode_Checked(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        _mode = TimedBlockRadio.IsChecked == true ? ScheduledMode.TimedBlock :
            DelayedUnblockRadio.IsChecked == true ? ScheduledMode.DelayedUnblock : ScheduledMode.DelayedBlock;
        RefreshAll(resetAck: true);
    }

    private void Kind_Checked(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        _kind = NetworkKindRadio.IsChecked == true ? RuleTargetKind.NetworkAddress : RuleTargetKind.Program;
        RefreshAll(resetAck: true);
    }

    private void Direction_Checked(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        _directions = BothRadio.IsChecked == true ? BlockDirections.Both :
            InboundRadio.IsChecked == true ? BlockDirections.Inbound : BlockDirections.Outbound;
        RefreshAll(resetAck: false);
    }

    private void QuickMinutes_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string tag })
            MinutesTextBox.Text = tag;
    }

    private void Minutes_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_initialized) return;
        RefreshAll(resetAck: false);
    }

    private void Ack_Changed(object sender, RoutedEventArgs e)
    {
        if (_initialized) UpdateConfirmState();
    }

    private void RefreshAll(bool resetAck)
    {
        if (!_initialized) return;
        DirectionPanel.IsEnabled = _mode != ScheduledMode.DelayedUnblock;
        if (_mode == ScheduledMode.DelayedUnblock)
            DirectionPanel.Opacity = 0.65;
        else
            DirectionPanel.Opacity = 1;

        var rows = BuildRows();
        TargetGrid.ItemsSource = rows;
        var eligible = rows.Where(r => r.IsEligible).Select(r => r.Option).ToList();
        SelectedTargets = eligible;
        SelectedMinutes = _minutes;
        SelectedMode = _mode;
        SelectedKind = _kind;
        SelectedDirections = _mode == ScheduledMode.DelayedUnblock ? BlockDirections.None : _directions;
        TargetListSummary.Text = $"可安排 {eligible.Count} 项 / 共 {CurrentOptions.Count} 项";

        var needsRiskAck = _mode != ScheduledMode.DelayedUnblock &&
                           eligible.Any(o => o.Risk >= RiskLevel.High || o.IsNetworkBroad);
        RiskPanel.Visibility = needsRiskAck ? Visibility.Visible : Visibility.Collapsed;
        if (resetAck || !needsRiskAck)
            HighRiskAckCheckBox.IsChecked = false;
        RiskText.Text = needsRiskAck
            ? "所选对象包含系统/服务进程或高影响网络目标。阻断可能影响系统功能、登录、更新或设备发现。请确认确实需要继续。"
            : string.Empty;

        var validTime = DurationValidator.TryParseMinutes(MinutesTextBox.Text, out _minutes, out var timeError);
        _timeValid = validTime;
        TimeErrorText.Text = validTime ? string.Empty : timeError ?? "分钟数无效。";
        TimeErrorText.Visibility = validTime ? Visibility.Collapsed : Visibility.Visible;
        var dueLocal = DateTimeOffset.Now.AddMinutes(Math.Max(0, _minutes));
        PreviewTimeText.Text = validTime
            ? $"预计执行时间：{dueLocal:yyyy-MM-dd HH:mm:ss}（当前时间 + {_minutes} 分钟）。管理员授权和规则设置可能引入少量延迟，实际时间以历史记录为准。"
            : string.Empty;

        if (eligible.Count == 0)
        {
            SummaryText.Text = _mode switch
            {
                ScheduledMode.DelayedUnblock => "当前没有既有本工具规则可用于延迟解除。请选择有生效规则的对象，或先在“解除禁止”中处理。",
                _ => "当前对象不满足此模式条件。请檢查对象是否已有规则或定时任务，并切换其他模式。"
            };
            ScopeSummaryText.Text = string.Empty;
            FooterHint.Text = "没有可安排的对象，不会创建任务。";
        }
        else
        {
            var count = eligible.Count;
            var window = TimeDisplay.LocalDateTime(dueLocal);
            SummaryText.Text = _mode switch
            {
                ScheduledMode.DelayedBlock =>
                    $"将在 {_minutes} 分钟后（{window}）为 {count} 个对象创建{_directions.ToChinese()}阻断规则。它不会自动解除。",
                ScheduledMode.DelayedUnblock =>
                    $"将在 {_minutes} 分钟后（{window}）解除 {count} 个对象上由本工具创建的有效规则。每个任务只解除创建时关联的规则。",
                ScheduledMode.TimedBlock =>
                    $"现在为 {count} 个对象创建{_directions.ToChinese()}阻断规则，并在 {_minutes} 分钟后（{window}）自动解除本工具创建的相应规则。",
                _ => string.Empty
            };
            ScopeSummaryText.Text = _kind == RuleTargetKind.Program
                ? "程序路径规则会影响该可执行文件启动的全部实例，并对所有用户生效；不只是所选 PID。"
                : "远程目标规则会影响所有访问该地址范围的应用程序，不限制端口；不只是所选连接。";
            FooterHint.Text = $"将创建 {count} 个独立定时任务并请求管理员授权。实际执行将在系统计划任务触发后记录。";
        }

        HeaderSubtitle.Text = _mode switch
        {
            ScheduledMode.DelayedBlock => "延迟禁止：倒计时结束前不会阻断；到时创建规则后保持阻断。",
            ScheduledMode.DelayedUnblock => "延迟解除禁止：用于已有本工具阻断规则的对象；到时恢复本工具创建的规则。",
            ScheduledMode.TimedBlock => "限时禁止：现在阻断，到时自动解除本工具创建的规则。",
            _ => string.Empty
        };
        UpdateConfirmState();
    }

    private List<ScheduleTargetRow> BuildRows()
    {
        var rows = new List<ScheduleTargetRow>();
        foreach (var option in CurrentOptions)
        {
            var (eligible, reason) = Evaluate(option);
            rows.Add(new ScheduleTargetRow
            {
                Option = option,
                IsEligible = eligible,
                EligibilityText = eligible ? "可安排" : "不可安排",
                Detail = eligible ? option.Detail : $"{option.Detail} · {reason}",
                CurrentStateText = BuildCurrentState(option)
            });
        }
        return rows;
    }

    private (bool Eligible, string? Reason) Evaluate(UiTargetOption option)
    {
        if (_mode == ScheduledMode.DelayedUnblock)
        {
            if (option.PendingTaskCount > 0) return (false, "对象已有待执行任务");
            if (option.HasInconsistentRule) return (false, "存在状态异常规则，请先检查");
            if (option.ActiveDirections == BlockDirections.None)
                return (false, option.HasManagedActiveRule
                    ? "仅有非精确匹配的网络规则，请在规则列表中解除"
                    : "没有本工具创建的有效阻断规则");
            return (true, null);
        }

        if (!option.CanScheduleBlock)
            return (false, option.IneligibleReason ?? "当前对象无法安排阻断");
        if (option.HasManagedActiveRule)
            return (false, "对象已有本工具规则，请改用“延迟解除”");
        if (option.PendingTaskCount > 0)
            return (false, "对象已有待执行任务");
        return (true, null);
    }

    private static string BuildCurrentState(UiTargetOption option)
    {
        var parts = new List<string>();
        if (option.ActiveDirections != BlockDirections.None)
            parts.Add($"已禁止（{option.ActiveDirections.ToChinese()}）");
        else if (option.HasManagedActiveRule)
            parts.Add("有本工具规则，但未验证生效");
        else
            parts.Add("未禁止");
        if (option.PendingTaskCount > 0)
            parts.Add($"有待执行任务 {option.PendingTaskCount}");
        if (option.HasInconsistentRule)
            parts.Add("含状态异常规则");
        return string.Join(" · ", parts);
    }

    private void UpdateConfirmState()
    {
        var canConfirm = _timeValid && SelectedTargets.Count > 0 &&
                         (RiskPanel.Visibility != Visibility.Visible || HighRiskAckCheckBox.IsChecked == true);
        ConfirmButton.IsEnabled = canConfirm;
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (!_timeValid || SelectedTargets.Count == 0) return;
        if (RiskPanel.Visibility == Visibility.Visible && HighRiskAckCheckBox.IsChecked != true) return;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
