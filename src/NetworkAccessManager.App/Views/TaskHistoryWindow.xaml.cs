using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.App.Services;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Firewall;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.App.Views;

public sealed class HistoryRowViewModel
{
    public HistoryRowViewModel(OperationHistoryEvent historyEvent)
    {
        Event = historyEvent;
    }

    public OperationHistoryEvent Event { get; }
    public string TimeText => Event.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string Operation => Event.Operation;
    public string TargetText => Event.Target ?? Event.TargetPath ?? "—";
    public string OutcomeText => Event.Outcome switch
    {
        OperationOutcome.Success => "成功",
        OperationOutcome.Warning => "警告",
        OperationOutcome.Failure => "失败",
        _ => "信息"
    };
    public Brush OutcomeBrush => UiBrushes.ForOutcome(Event.Outcome);
    public string Message => Event.Message;
    public string Detail => Event.Detail ?? "—";
    public string Source => Event.Source;
    public string PlannedText => Event.PlannedUtc is null ? "—" : Event.PlannedUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string ActualText => Event.ActualUtc is null ? "—" : Event.ActualUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string Identifiers
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(Event.RuleId)) parts.Add("规则 " + Shorten(Event.RuleId));
            if (!string.IsNullOrWhiteSpace(Event.TaskId)) parts.Add("任务 " + Shorten(Event.TaskId));
            return parts.Count == 0 ? "—" : string.Join(" · ", parts);
        }
    }

    public string SearchText => string.Join(' ', TimeText, Operation, TargetText, OutcomeText, Message, Detail, Source, Identifiers);

    private static string Shorten(string id) => id.Length > 16 ? id[..16] + "…" : id;
}

public partial class TaskHistoryWindow : Window
{
    private readonly AppPaths _paths;
    private readonly IAppLog _log;
    private readonly StateRepository _store;
    private readonly ComFirewallManager _firewall = new();
    private readonly UiOperationService _operations;
    private readonly bool _pendingOnly;
    private List<ScheduledTaskView> _tasks = new();
    private List<RuleStatusView> _rules = new();
    private List<HistoryRowViewModel> _history = new();
    private List<FilterOption> _filterOptions = new();
    private bool _loading;
    private bool _suppressFilterEvents;
    private string? _forcedFilterKey;
    private FirewallAvailability? _availability;

    public TaskHistoryWindow(AppPaths paths, IAppLog log, bool pendingOnly = false)
    {
        InitializeComponent();
        _paths = paths;
        _log = log;
        _store = new StateRepository(paths);
        _operations = new UiOperationService(paths, log);
        _pendingOnly = pendingOnly;
        if (pendingOnly)
            HistoryTabs.SelectedIndex = 0;
        _forcedFilterKey = pendingOnly ? "pending" : null;
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        await LoadAsync().ConfigureAwait(true);
    }

    private async Task LoadAsync()
    {
        if (_loading) return;
        SetBusy(true);
        try
        {
            var result = await Task.Run(() =>
            {
                StoreReadResult? read = null;
                string? stateError = null;
                try { read = _store.ReadState(); }
                catch (Exception ex) { stateError = ex.Message; }
                var state = read?.State ?? new AppState();
                var activeRules = state.Rules.Where(r => r.Status == ManagedRuleStatus.Active).ToList();
                FirewallInspectionBatch batch;
                try
                {
                    if (activeRules.Count > 0)
                        batch = _firewall.InspectRules(activeRules);
                    else
                        batch = new FirewallInspectionBatch
                        {
                            Availability = _firewall.GetAvailability(),
                            Inspections = new Dictionary<string, FirewallRuleInspection>(StringComparer.OrdinalIgnoreCase),
                            CheckedUtc = DateTimeOffset.UtcNow
                        };
                }
                catch (Exception ex)
                {
                    batch = new FirewallInspectionBatch
                    {
                        Availability = new FirewallAvailability
                        {
                            StatusText = "读取失败",
                            Error = ex.Message,
                            IsAvailable = false,
                            CanReadRules = false
                        },
                        Inspections = activeRules.ToDictionary(
                            r => r.RuleId,
                            r => new FirewallRuleInspection
                            {
                                RuleId = r.RuleId,
                                FirewallRuleName = r.FirewallRuleName,
                                State = RuleInspectionState.Unknown,
                                Detail = "读取防火墙失败：" + ex.Message
                            },
                            StringComparer.OrdinalIgnoreCase),
                        CheckedUtc = DateTimeOffset.UtcNow
                    };
                }
                return (read, stateError, batch);
            }).ConfigureAwait(true);

            _availability = result.batch.Availability;
            _tasks = new UiPolicyEvaluator(result.Item1?.State ?? new AppState(), result.batch, DateTimeOffset.UtcNow).Tasks.ToList();
            _rules = new UiPolicyEvaluator(result.Item1?.State ?? new AppState(), result.batch, DateTimeOffset.UtcNow).Rules.ToList();            var events = result.Item1?.State.Events ?? new List<OperationHistoryEvent>();
            _history = events.OrderByDescending(e => e.TimestampUtc).Select(e => new HistoryRowViewModel(e)).ToList();

            var pending = _tasks.Count(t => t.Record.Status == ScheduledTaskStatus.Pending);
            var failed = _tasks.Count(t => t.Record.Status == ScheduledTaskStatus.Failed);
            var activeRules = _rules.Count(r => r.IsActiveRecord);
            var inconsistent = _rules.Count(r => r.IsActiveRecord && !r.IsVerified);
            SummaryText.Text = $"任务 {_tasks.Count}（待执行 {pending}，失败 {failed}） · 受管规则 {activeRules} 条（状态不一致 {inconsistent}） · 操作历史 {_history.Count} 条";
            FirebaseStatusText();
            if (result.stateError is not null)
            {
                FirewallStateText.Text = "状态数据读取失败：" + result.stateError;
                FirewallStateText.Foreground = UiBrushes.Red;
            }
            UpdateFilterOptions();
            ApplyFilter();
        }
        catch (Exception ex)
        {
            _log.Error("History", "加载任务与历史失败", ex);
            SummaryText.Text = "加载失败：" + ex.Message;
            MessageBox.Show(this, "加载任务与历史失败：\n" + ex.Message, "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void FirebaseStatusText()
    {
        if (_availability is null) return;
        FirewallStateText.Text = _availability.StatusText + (_availability.Error is null ? string.Empty : " · " + _availability.Error);
        FirewallStateText.Foreground = _availability.IsAvailable && _availability.CanReadRules ? UiBrushes.MutedText : UiBrushes.Orange;
    }

    private void UpdateFilterOptions()
    {
        _filterOptions = HistoryTabs.SelectedIndex switch
        {
            0 => new List<FilterOption>
            {
                new() { Key = "all", Label = "全部任务" },
                new() { Key = "pending", Label = "待执行 / 执行中" },
                new() { Key = "completed", Label = "已完成" },
                new() { Key = "failed", Label = "执行失败" },
                new() { Key = "cancelled", Label = "已取消" }
            },
            1 => new List<FilterOption>
            {
                new() { Key = "all", Label = "全部规则" },
                new() { Key = "active", Label = "实际生效" },
                new() { Key = "inconsistent", Label = "状态不一致 / 未知" },
                new() { Key = "removed", Label = "已解除 / 历史" }
            },
            _ => new List<FilterOption>
            {
                new() { Key = "all", Label = "全部记录" },
                new() { Key = "success", Label = "成功 / 信息" },
                new() { Key = "failure", Label = "失败" },
                new() { Key = "warning", Label = "警告" }
            }
        };
        _suppressFilterEvents = true;
        FilterComboBox.ItemsSource = _filterOptions;
        var preferredKey = _forcedFilterKey;
        _forcedFilterKey = null;
        FilterComboBox.SelectedValue = _filterOptions.Any(o => o.Key == preferredKey)
            ? preferredKey
            : _filterOptions[0].Key;
        _suppressFilterEvents = false;
    }

    private void ApplyFilter()
    {
        var search = SearchBox.Text;
        var key = FilterComboBox.SelectedValue as string ?? "all";

        var tasks = _tasks.AsEnumerable();
        tasks = key switch
        {
            "pending" => tasks.Where(t => t.IsPendingLike),
            "completed" => tasks.Where(t => t.Record.Status == ScheduledTaskStatus.Succeeded),
            "failed" => tasks.Where(t => t.IsFailure),
            "cancelled" => tasks.Where(t => t.Record.Status == ScheduledTaskStatus.Cancelled),
            _ => tasks
        };
        if (!string.IsNullOrWhiteSpace(search))
            tasks = tasks.Where(t => t.SearchText.Contains(search.Trim(), StringComparison.CurrentCultureIgnoreCase));
        TaskGrid.ItemsSource = tasks.Select(t => t).ToList();

        var rules = _rules.AsEnumerable();
        rules = key switch
        {
            "active" => rules.Where(r => r.IsActiveRecord && r.IsVerified),
            "inconsistent" => rules.Where(r => r.IsActiveRecord && !r.IsVerified),
            "removed" => rules.Where(r => !r.IsActiveRecord),
            _ => rules
        };
        if (!string.IsNullOrWhiteSpace(search))
            rules = rules.Where(r => r.SearchText.Contains(search.Trim(), StringComparison.CurrentCultureIgnoreCase));
        RuleGrid.ItemsSource = rules.Select(r => r).ToList();

        var history = _history.AsEnumerable();
        history = key switch
        {
            "success" => history.Where(h => h.Event.Outcome is OperationOutcome.Success or OperationOutcome.Info),
            "failure" => history.Where(h => h.Event.Outcome == OperationOutcome.Failure),
            "warning" => history.Where(h => h.Event.Outcome == OperationOutcome.Warning),
            _ => history
        };
        if (!string.IsNullOrWhiteSpace(search))
            history = history.Where(h => h.SearchText.Contains(search.Trim(), StringComparison.CurrentCultureIgnoreCase));
        HistoryGrid.ItemsSource = history.ToList();

        var taskCount = HistoryTabs.SelectedIndex switch
        {
            0 => CountItems(TaskGrid),
            1 => CountItems(RuleGrid),
            _ => CountItems(HistoryGrid)
        };
        VisibleCountText.Text = $"当前页显示 {taskCount} 条 · 任务总计 {_tasks.Count} · 待执行 {_tasks.Count(t => t.Record.Status == ScheduledTaskStatus.Pending)} · 规则总计 {_rules.Count}";
        UpdateSelectionState();
    }

    private static int CountItems(ItemsControl grid) => grid.Items.Count;

    private void UpdateSelectionState()
    {
        var inTasks = HistoryTabs.SelectedIndex == 0;
        var inRules = HistoryTabs.SelectedIndex == 1;
        var inHistory = HistoryTabs.SelectedIndex == 2;
        CancelTaskButton.IsEnabled = inTasks && TaskGrid.SelectedItems.OfType<ScheduledTaskView>().Any(t => t.Record.Status == ScheduledTaskStatus.Pending);
        UnblockRuleButton.IsEnabled = inRules && RuleGrid.SelectedItems.OfType<RuleStatusView>().Any(r => r.IsActiveRecord);
        CopyDetailsButton.IsEnabled = !string.IsNullOrWhiteSpace(SelectionDetailText.Text);

        SelectionDetailText.Text = string.Empty;
        if (inTasks && TaskGrid.SelectedItem is ScheduledTaskView task)
        {
            SelectionDetailText.Text = $"任务 {task.TaskId} · {task.ModeText} · {task.StatusText}\n" +
                                       $"对象：{task.TargetText}（{task.TargetKindText}） · 方向 {task.DirectionText}\n" +
                                       $"计划：{task.PlannedText} · 实际开始：{task.StartedText} · 完成：{task.CompletedText}\n" +
                                       $"结果：{task.ResultText}\n系统任务名：{task.ScheduledTaskName}";
        }
        else if (inRules && RuleGrid.SelectedItem is RuleStatusView rule)
        {
            SelectionDetailText.Text = $"规则 {rule.RuleId} · {rule.TargetKindText} · {rule.DirectionText} · {rule.StatusText}\n" +
                                       $"对象：{rule.TargetText}\n创建：{rule.CreatedText} · 防火墙规则名：{rule.FirewallRuleName}\n" +
                                       $"校验：{rule.StatusDetail}";
        }
        else if (inHistory && HistoryGrid.SelectedItem is HistoryRowViewModel history)
        {
            var detail = string.IsNullOrWhiteSpace(history.Detail) ? "—" : history.Detail;
            SelectionDetailText.Text = $"时间：{history.TimeText} · {history.Operation} · {history.OutcomeText} · 来源：{history.Source}\n" +
                                       $"对象：{history.TargetText}\n计划：{history.PlannedText} · 实际：{history.ActualText}\n" +
                                       $"消息：{history.Message}\n详情：{detail}";
        }
        CopyDetailsButton.IsEnabled = !string.IsNullOrWhiteSpace(SelectionDetailText.Text);
    }

    private void HistoryTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        UpdateFilterOptions();
        ApplyFilter();
    }

    private void Filter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || _suppressFilterEvents) return;
        ApplyFilter();
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyFilter();
    }

    private void TaskGrid_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateSelectionState();
    private void RuleGrid_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateSelectionState();
    private void HistoryGrid_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateSelectionState();

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync().ConfigureAwait(true);

    private async void CancelTask_Click(object sender, RoutedEventArgs e)
    {
        var selected = TaskGrid.SelectedItems.OfType<ScheduledTaskView>().ToList();
        var cancellable = selected.Where(t => t.Record.Status == ScheduledTaskStatus.Pending).ToList();
        if (cancellable.Count == 0)
        {
            MessageBox.Show(this, "请选择至少一个处于“等待执行”状态的任务。执行中或已结束任务不能取消。", "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var skipped = selected.Count - cancellable.Count;
        var prompt = $"将取消 {cancellable.Count} 个待执行定时任务。\n\n" +
                     "选择“是”：取消任务，并立即解除与该任务关联、仍生效的本工具阻断规则（如存在）。\n" +
                     "选择“否”：只取消任务，保留当前规则状态（对象可能继续被阻断）。\n" +
                     "选择“取消”：不执行任何操作。\n\n" +
                     "取消后，任务会先写入“已取消”状态；即使 Windows 计划任务记录删除失败，后续触发也不会再修改规则。" +
                     (skipped > 0 ? $"\n\n另有 {skipped} 个非待执行任务将被跳过。" : string.Empty);
        var answer = MessageBox.Show(this, prompt, "确认取消定时任务", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Cancel) return;
        var unblock = answer == MessageBoxResult.Yes;

        var actions = cancellable.Select(task => new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.CancelScheduledTask,
            TaskId = task.TaskId,
            UnblockRulesOnCancel = unblock
        }).ToList();

        await ExecuteActionsAsync(actions, "取消定时任务").ConfigureAwait(true);
    }

    private async void UnblockRule_Click(object sender, RoutedEventArgs e)
    {
        var selected = RuleGrid.SelectedItems.OfType<RuleStatusView>().Where(r => r.IsActiveRecord).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "请选择至少一条仍处于本工具登记有效状态的规则。", "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var keys = selected.Select(r => (r.Record.TargetKind, r.Record.Target.ToLowerInvariant())).ToHashSet();
        var expanded = _rules.Where(r => r.IsActiveRecord && keys.Contains((r.Record.TargetKind, r.Record.Target.ToLowerInvariant()))).ToList();
        var targets = expanded
            .GroupBy(r => (r.Record.TargetKind, Target: r.Record.Target.ToLowerInvariant()))
            .Select(g =>
            {
                var list = g.ToList();
                var first = list[0].Record;
                return new UiUnblockTarget
                {
                    Kind = first.TargetKind,
                    Value = first.Target,
                    Display = first.TargetKind == RuleTargetKind.Program ? System.IO.Path.GetFileName(first.Target) : first.Target,
                    Detail = first.TargetKind == RuleTargetKind.Program ? first.Target : "网络目标规则会影响所有访问该地址范围的应用程序。",
                    Rules = list,
                    HasInconsistentRule = list.Any(r => !r.IsVerified)
                };
            })
            .ToList();

        var dialog = new UnblockDialog(targets) { Owner = this };
        if (dialog.ShowDialog() != true) return;
        var actions = dialog.SelectedTargets.Select(t => new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.UnblockTarget,
            TargetKind = t.Kind,
            Target = t.Value
        }).ToList();
        await ExecuteActionsAsync(actions, "解除本工具规则").ConfigureAwait(true);
    }

    private async Task ExecuteActionsAsync(IReadOnlyList<ElevatedAction> actions, string label)
    {
        SetBusy(true);
        try
        {
            var outcome = await _operations.ExecuteAsync(actions, label).ConfigureAwait(true);
            var dialog = new OperationResultDialog(outcome) { Owner = this };
            dialog.ShowDialog();
            await LoadAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _log.Error("History", "执行历史窗口操作失败", ex);
            MessageBox.Show(this, "操作失败：\n" + ex.Message, "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        _loading = busy;
        RefreshButton.IsEnabled = !busy;
        if (busy)
        {
            CancelTaskButton.IsEnabled = false;
            UnblockRuleButton.IsEnabled = false;
            LoadingBar.Visibility = Visibility.Visible;
            SelectionDetailText.Text = "正在读取真实状态或等待管理员操作结果…";
        }
        else
        {
            LoadingBar.Visibility = Visibility.Collapsed;
            UpdateSelectionState();
        }
    }

    private void CopyDetails_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(SelectionDetailText.Text))
                Clipboard.SetText(SelectionDetailText.Text);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "复制失败：" + ex.Message, "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
