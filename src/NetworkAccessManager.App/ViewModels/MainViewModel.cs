using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.App.Services;
using NetworkAccessManager.App.ViewModels;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.ViewModels;

public enum SelectionScope
{
    None,
    AppProcesses,
    SystemProcesses,
    Connections
}

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly AppPaths _paths;
    private readonly IAppLog _log;
    private readonly UiMonitorService _monitor;
    private readonly UiOperationService _operationService;
    private readonly StateRepository _store;
    private readonly SettingsStore _settingsStore;
    private readonly DispatcherTimer _timer = new();
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly Dictionary<string, ProcessRowViewModel> _processRows = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ConnectionRowViewModel> _connectionRows = new(StringComparer.OrdinalIgnoreCase);
    private UiSettings _settings = new();
    private UiMonitorSnapshot? _snapshot;
    private UiPolicyEvaluator? _policyEvaluator;
    private bool _disposed;
    private bool _initialized;
    private bool _loggedStartupSummary;
    private bool _isRefreshing;
    private bool _isBusyOperation;

    private IReadOnlyList<ProcessRowViewModel> _selectedApp = Array.Empty<ProcessRowViewModel>();
    private IReadOnlyList<ProcessRowViewModel> _selectedSystem = Array.Empty<ProcessRowViewModel>();
    private IReadOnlyList<ConnectionRowViewModel> _selectedConnections = Array.Empty<ConnectionRowViewModel>();
    private SelectionScope _activeScope;

    private string _appProcessSearch = string.Empty;
    private string _systemProcessSearch = string.Empty;
    private string _connectionSearch = string.Empty;
    private string _appProcessFilterKey = "all";
    private string _systemProcessFilterKey = "all";
    private string _connectionFilterKey = "all";

    private string _monitorStatusText = "尚未启动";
    private Brush _monitorStatusBrush = UiBrushes.Gray;
    private string _lastRefreshText = "尚未刷新";
    private string _statusMessage = "正在初始化…";
    private Brush _statusBrush = UiBrushes.MutedText;
    private string _warningText = string.Empty;
    private string _warningTooltip = string.Empty;
    private bool _hasWarnings;
    private Brush _warningForeground = UiBrushes.Orange;
    private string _firewallStatusText = "未检查";
    private string _firewallDetailText = "Windows 防火墙状态未知";
    private Brush _firewallStatusBrush = UiBrushes.Gray;
    private string? _firewallError;
    private int _pendingTaskCount;
    private string _pendingTaskText = "待执行任务 0";
    private string _appProcessCountText = "0";
    private string _systemProcessCountText = "0";
    private string _connectionCountText = "0";
    private string _appProcessVisibleText = "显示 0 / 0";
    private string _systemProcessVisibleText = "显示 0 / 0";
    private string _connectionVisibleText = "显示 0 / 0";
    private string _selectionTitle = "未选择对象";
    private string _selectionSubtitle = "在表格中选择一行或多行以查看详情。";
    private string _selectionLine1 = string.Empty;
    private string _selectionLine2 = string.Empty;
    private string _selectionLine3 = string.Empty;
    private string _selectionLine4 = string.Empty;
    private string _selectedCountText = "已选 0 项";
    private string? _selectedPath;
    private string _busyText = string.Empty;
    private string _lastOperationSummary = "尚无操作";
    private Brush _lastOperationBrush = UiBrushes.MutedText;
    private string _lastErrorMessage = string.Empty;
    private bool _hasInitialLoadError;
    private string _startupNotice = string.Empty;

    public MainViewModel(AppPaths paths, IAppLog log, string? loggingError)
    {
        _paths = paths;
        _log = log;
        _store = new StateRepository(paths);
        _settingsStore = new SettingsStore(paths, log);
        _monitor = new UiMonitorService(paths, log);
        _operationService = new UiOperationService(paths, log);

        AppProcesses = new ObservableCollection<ProcessRowViewModel>();
        SystemProcesses = new ObservableCollection<ProcessRowViewModel>();
        Connections = new ObservableCollection<ConnectionRowViewModel>();
        AppProcessView = CreateProcessView(AppProcesses, FilterAppProcess);
        SystemProcessView = CreateProcessView(SystemProcesses, FilterSystemProcess);
        ConnectionView = new ListCollectionView(Connections)
        {
            Filter = FilterConnection
        };
        ConnectionView.SortDescriptions.Add(new SortDescription(nameof(ConnectionRowViewModel.ProcessName), ListSortDirection.Ascending));
        ConnectionView.SortDescriptions.Add(new SortDescription(nameof(ConnectionRowViewModel.LocalPortText), ListSortDirection.Ascending));

        AppProcessFilters =
        [
            new FilterOption { Key = "all", Label = "全部" },
            new FilterOption { Key = "network", Label = "有网络连接" },
            new FilterOption { Key = "blocked", Label = "已禁止" },
            new FilterOption { Key = "tasks", Label = "有定时任务" },
            new FilterOption { Key = "issues", Label = "失败或状态异常" }
        ];
        SystemProcessFilters =
        [
            new FilterOption { Key = "all", Label = "全部" },
            new FilterOption { Key = "network", Label = "有网络连接" },
            new FilterOption { Key = "blocked", Label = "已禁止" },
            new FilterOption { Key = "tasks", Label = "有定时任务" },
            new FilterOption { Key = "issues", Label = "失败或状态异常" },
            new FilterOption { Key = "critical", Label = "关键系统组件" }
        ];
        ConnectionFilters =
        [
            new FilterOption { Key = "all", Label = "全部" },
            new FilterOption { Key = "active", Label = "已连接" },
            new FilterOption { Key = "listening", Label = "监听 / 端点" },
            new FilterOption { Key = "blocked", Label = "策略已禁止" },
            new FilterOption { Key = "tasks", Label = "有定时任务" },
            new FilterOption { Key = "issues", Label = "失败或状态异常" }
        ];

        _startupNotice = loggingError is null ? string.Empty : $"日志目录不可写：{loggingError}";
        VersionText = GetVersionText();
        WindowTitle = $"网络访问管理器 {VersionText}";
        DataDirectory = paths.RootDirectory;
        LogDirectory = paths.LogsDirectory;
        IsElevated = WindowsPrivilege.IsAdministrator();
        CurrentUserText = WindowsPrivilege.CurrentUserName();
        PrivilegeStatusText = IsElevated ? "已取得管理员权限" : "普通权限";
        PrivilegeBrush = IsElevated ? UiBrushes.Green : UiBrushes.Blue;
        PrivilegeHint = IsElevated
            ? "当前窗口已具有管理员权限；规则操作仍通过独立辅助进程完成。"
            : "当前窗口是普通权限。查看进程/连接不需要管理员权限；创建、解除规则和设置定时任务时，会通过标准 Windows UAC 请求授权。";

        _timer.Tick += OnTimerTick;
        RaiseHeaderProperties();
        RefreshSelectionDetails();
    }

    public ObservableCollection<ProcessRowViewModel> AppProcesses { get; }
    public ObservableCollection<ProcessRowViewModel> SystemProcesses { get; }
    public ObservableCollection<ConnectionRowViewModel> Connections { get; }
    public ListCollectionView AppProcessView { get; }
    public ListCollectionView SystemProcessView { get; }
    public ListCollectionView ConnectionView { get; }
    public IReadOnlyList<FilterOption> AppProcessFilters { get; }
    public IReadOnlyList<FilterOption> SystemProcessFilters { get; }
    public IReadOnlyList<FilterOption> ConnectionFilters { get; }

    public string WindowTitle { get; }
    public string VersionText { get; }
    public string DataDirectory { get; }
    public string LogDirectory { get; }
    public string CurrentUserText { get; }
    public bool IsElevated { get; }
    public string PrivilegeStatusText { get; }
    public string PrivilegeHint { get; }
    public Brush PrivilegeBrush { get; }

    public UiMonitorSnapshot? LastSnapshot => _snapshot;
    public UiPolicyEvaluator? PolicyEvaluator => _policyEvaluator;

    private bool _selectionCanBlock;
    private bool _selectionCanUnblock;
    private bool _selectionCanSchedule;

    public bool IsRefreshing
    {
        get => _isRefreshing;
        private set
        {
            if (!SetProperty(ref _isRefreshing, value)) return;
            OnPropertyChanged(nameof(IsBusy));
            OnPropertyChanged(nameof(CanBlockSelected));
            OnPropertyChanged(nameof(CanUnblockSelected));
            OnPropertyChanged(nameof(CanScheduleSelected));
            OnPropertyChanged(nameof(CanCancelTasks));
            OnPropertyChanged(nameof(IsRefreshButtonEnabled));
        }
    }

    public bool IsBusyOperation
    {
        get => _isBusyOperation;
        private set
        {
            if (!SetProperty(ref _isBusyOperation, value)) return;
            OnPropertyChanged(nameof(IsBusy));
            OnPropertyChanged(nameof(CanBlockSelected));
            OnPropertyChanged(nameof(CanUnblockSelected));
            OnPropertyChanged(nameof(CanScheduleSelected));
            OnPropertyChanged(nameof(CanCancelTasks));
            OnPropertyChanged(nameof(IsRefreshButtonEnabled));
        }
    }

    public bool IsBusy => IsRefreshing || IsBusyOperation;
    public bool IsRefreshButtonEnabled => !IsBusy;
    public string BusyText
    {
        get => _busyText;
        private set => SetProperty(ref _busyText, value);
    }

    public string MonitorStatusText
    {
        get => _monitorStatusText;
        private set => SetProperty(ref _monitorStatusText, value);
    }

    public Brush MonitorStatusBrush
    {
        get => _monitorStatusBrush;
        private set => SetProperty(ref _monitorStatusBrush, value);
    }

    public string LastRefreshText
    {
        get => _lastRefreshText;
        private set => SetProperty(ref _lastRefreshText, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    public Brush StatusBrush
    {
        get => _statusBrush;
        private set => SetProperty(ref _statusBrush, value);
    }

    public string WarningText
    {
        get => _warningText;
        private set => SetProperty(ref _warningText, value);
    }

    public string WarningTooltip
    {
        get => _warningTooltip;
        private set => SetProperty(ref _warningTooltip, value);
    }

    public bool HasWarnings
    {
        get => _hasWarnings;
        private set => SetProperty(ref _hasWarnings, value);
    }

    public Brush WarningForeground
    {
        get => _warningForeground;
        private set => SetProperty(ref _warningForeground, value);
    }

    public string FirewallStatusText
    {
        get => _firewallStatusText;
        private set => SetProperty(ref _firewallStatusText, value);
    }

    public string FirewallDetailText
    {
        get => _firewallDetailText;
        private set => SetProperty(ref _firewallDetailText, value);
    }

    public Brush FirewallStatusBrush
    {
        get => _firewallStatusBrush;
        private set => SetProperty(ref _firewallStatusBrush, value);
    }

    public string? FirewallError
    {
        get => _firewallError;
        private set => SetProperty(ref _firewallError, value);
    }

    public int PendingTaskCount
    {
        get => _pendingTaskCount;
        private set
        {
            if (!SetProperty(ref _pendingTaskCount, value)) return;
            OnPropertyChanged(nameof(CanCancelTasks));
        }
    }    public string PendingTaskText
    {
        get => _pendingTaskText;
        private set => SetProperty(ref _pendingTaskText, value);
    }

    public string AppProcessCountText
    {
        get => _appProcessCountText;
        private set => SetProperty(ref _appProcessCountText, value);
    }

    public string SystemProcessCountText
    {
        get => _systemProcessCountText;
        private set => SetProperty(ref _systemProcessCountText, value);
    }

    public string ConnectionCountText
    {
        get => _connectionCountText;
        private set => SetProperty(ref _connectionCountText, value);
    }

    public string AppProcessVisibleText
    {
        get => _appProcessVisibleText;
        private set => SetProperty(ref _appProcessVisibleText, value);
    }

    public string SystemProcessVisibleText
    {
        get => _systemProcessVisibleText;
        private set => SetProperty(ref _systemProcessVisibleText, value);
    }

    public string ConnectionVisibleText
    {
        get => _connectionVisibleText;
        private set => SetProperty(ref _connectionVisibleText, value);
    }

    public string SelectionTitle
    {
        get => _selectionTitle;
        private set => SetProperty(ref _selectionTitle, value);
    }

    public string SelectionSubtitle
    {
        get => _selectionSubtitle;
        private set => SetProperty(ref _selectionSubtitle, value);
    }

    public string SelectionLine1
    {
        get => _selectionLine1;
        private set => SetProperty(ref _selectionLine1, value);
    }

    public string SelectionLine2
    {
        get => _selectionLine2;
        private set => SetProperty(ref _selectionLine2, value);
    }

    public string SelectionLine3
    {
        get => _selectionLine3;
        private set => SetProperty(ref _selectionLine3, value);
    }

    public string SelectionLine4
    {
        get => _selectionLine4;
        private set => SetProperty(ref _selectionLine4, value);
    }

    public string SelectedCountText
    {
        get => _selectedCountText;
        private set => SetProperty(ref _selectedCountText, value);
    }

    public string? SelectedPath
    {
        get => _selectedPath;
        private set
        {
            if (!SetProperty(ref _selectedPath, value)) return;
            OnPropertyChanged(nameof(HasSelectedPath));
        }
    }

    public bool HasSelectedPath => !string.IsNullOrWhiteSpace(SelectedPath);
    public bool HasSelection => ActiveSelectedObjects.Count > 0;

    public bool CanBlockSelected => !IsBusy && _selectionCanBlock;
    public bool CanUnblockSelected => !IsBusy && _selectionCanUnblock;
    public bool CanScheduleSelected => !IsBusy && _selectionCanSchedule;
    public bool CanCancelTasks => !IsBusy && PendingTaskCount > 0;

    public string LastOperationSummary
    {
        get => _lastOperationSummary;
        private set => SetProperty(ref _lastOperationSummary, value);
    }

    public Brush LastOperationBrush
    {
        get => _lastOperationBrush;
        private set => SetProperty(ref _lastOperationBrush, value);
    }

    public string LastErrorMessage
    {
        get => _lastErrorMessage;
        private set
        {
            if (!SetProperty(ref _lastErrorMessage, value)) return;
            OnPropertyChanged(nameof(HasLastError));
        }
    }

    public bool HasLastError => !string.IsNullOrWhiteSpace(LastErrorMessage);
    public bool HasInitialLoadError
    {
        get => _hasInitialLoadError;
        private set => SetProperty(ref _hasInitialLoadError, value);
    }

    public string AppProcessSearch
    {
        get => _appProcessSearch;
        set
        {
            if (!SetProperty(ref _appProcessSearch, value)) return;
            RefreshAppProcessFilters();
        }
    }

    public string SystemProcessSearch
    {
        get => _systemProcessSearch;
        set
        {
            if (!SetProperty(ref _systemProcessSearch, value)) return;
            RefreshSystemProcessFilters();
        }
    }

    public string ConnectionSearch
    {
        get => _connectionSearch;
        set
        {
            if (!SetProperty(ref _connectionSearch, value)) return;
            RefreshConnectionFilters();
        }
    }

    public string AppProcessFilterKey
    {
        get => _appProcessFilterKey;
        set
        {
            if (!SetProperty(ref _appProcessFilterKey, value)) return;
            RefreshAppProcessFilters();
        }
    }

    public string SystemProcessFilterKey
    {
        get => _systemProcessFilterKey;
        set
        {
            if (!SetProperty(ref _systemProcessFilterKey, value)) return;
            RefreshSystemProcessFilters();
        }
    }

    public string ConnectionFilterKey
    {
        get => _connectionFilterKey;
        set
        {
            if (!SetProperty(ref _connectionFilterKey, value)) return;
            RefreshConnectionFilters();
        }
    }

    public IReadOnlyList<ProcessRowViewModel> SelectedAppProcesses => _selectedApp;
    public IReadOnlyList<ProcessRowViewModel> SelectedSystemProcesses => _selectedSystem;
    public IReadOnlyList<ConnectionRowViewModel> SelectedConnections => _selectedConnections;
    public SelectionScope ActiveSelectionScope => _activeScope;

    public IReadOnlyList<ProcessRowViewModel> ActiveSelectedProcesses =>
        _activeScope == SelectionScope.AppProcesses ? _selectedApp :
        _activeScope == SelectionScope.SystemProcesses ? _selectedSystem :
        Array.Empty<ProcessRowViewModel>();

    public IReadOnlyList<ConnectionRowViewModel> ActiveSelectedConnections =>
        _activeScope == SelectionScope.Connections ? _selectedConnections : Array.Empty<ConnectionRowViewModel>();

    public IReadOnlyList<object> ActiveSelectedObjects =>
        _activeScope == SelectionScope.Connections
            ? _selectedConnections.Cast<object>().ToList()
            : ActiveSelectedProcesses.Cast<object>().ToList();

    public UiSettings SettingsSnapshot => new()
    {
        RefreshIntervalSeconds = _settings.RefreshIntervalSeconds,
        AutoRefreshEnabled = _settings.AutoRefreshEnabled,
        ShowConfirmationDetails = _settings.ShowConfirmationDetails,
        HistoryRetentionDays = _settings.HistoryRetentionDays
    };

    public async Task InitializeAsync()
    {
        if (_initialized) return;
        _initialized = true;

        var settingsResult = _settingsStore.Load();
        _settings = settingsResult.Settings;
        if (!string.IsNullOrWhiteSpace(settingsResult.Warning))
            AppendStartupWarning(settingsResult.Warning);
        _timer.Interval = TimeSpan.FromSeconds(_settings.RefreshIntervalSeconds);
        ConfigureTimer();
        await RefreshAsync(manual: true).ConfigureAwait(true);
    }

    public void SetSelection(SelectionScope scope, IEnumerable<ProcessRowViewModel>? processes = null, IEnumerable<ConnectionRowViewModel>? connections = null)
    {
        switch (scope)
        {
            case SelectionScope.AppProcesses:
                _selectedApp = processes?.ToList() ?? new List<ProcessRowViewModel>();
                break;
            case SelectionScope.SystemProcesses:
                _selectedSystem = processes?.ToList() ?? new List<ProcessRowViewModel>();
                break;
            case SelectionScope.Connections:
                _selectedConnections = connections?.ToList() ?? new List<ConnectionRowViewModel>();
                break;
            default:
                _selectedApp = Array.Empty<ProcessRowViewModel>();
                _selectedSystem = Array.Empty<ProcessRowViewModel>();
                _selectedConnections = Array.Empty<ConnectionRowViewModel>();
                break;
        }

        _activeScope = scope;
        RefreshSelectionDetails();
    }

    public void ClearSelection() => SetSelection(SelectionScope.None);

    public void ApplySettings(UiSettings settings)
    {
        settings.RefreshIntervalSeconds = Math.Clamp(settings.RefreshIntervalSeconds, 3, 120);
        _settings = new UiSettings
        {
            RefreshIntervalSeconds = settings.RefreshIntervalSeconds,
            AutoRefreshEnabled = settings.AutoRefreshEnabled,
            ShowConfirmationDetails = settings.ShowConfirmationDetails,
            HistoryRetentionDays = Math.Clamp(settings.HistoryRetentionDays, 7, 3650)
        };
        _timer.Interval = TimeSpan.FromSeconds(_settings.RefreshIntervalSeconds);
        ConfigureTimer();
        if (!_settingsStore.TrySave(_settings, out var error))
        {
            StatusMessage = "设置已应用，但保存失败：" + error;
            StatusBrush = UiBrushes.Orange;
        }
        else
        {
            StatusMessage = "设置已保存。";
            StatusBrush = UiBrushes.Green;
        }
        UpdateMonitorStatus();
    }

    public async Task RefreshAsync(bool manual = false)
    {
        if (_disposed) return;
        if (!await _refreshGate.WaitAsync(0).ConfigureAwait(true))
            return;
        try
        {
            IsRefreshing = true;
            BusyText = "正在读取真实进程、网络连接和防火墙状态…";
            StatusMessage = "正在刷新…";
            StatusBrush = UiBrushes.MutedText;
            LastErrorMessage = string.Empty;
            if (_settings.AutoRefreshEnabled)
            {
                MonitorStatusText = "正在刷新…";
                MonitorStatusBrush = UiBrushes.Blue;
            }

            var snapshot = await _monitor.CaptureAsync(_disposeCts.Token).ConfigureAwait(true);
            _snapshot = snapshot;
            ApplySnapshot(snapshot);
            var failCount = (snapshot.ProcessResult.Error is null ? 0 : 1) + (snapshot.NetworkResult.Error is null ? 0 : 1) + (snapshot.StateError is null ? 0 : 1);
            HasInitialLoadError = failCount == 3;
            LastRefreshText = snapshot.CapturedUtc.ToLocalTime().ToString("HH:mm:ss") + $"（{snapshot.Duration.TotalMilliseconds:0} ms）";
            if (failCount > 0)
            {
                StatusMessage = "刷新完成，但部分数据读取失败。请查看警告。";
                StatusBrush = UiBrushes.Orange;
            }
            else if (manual)
            {
                StatusMessage = $"刷新完成，耗时 {snapshot.Duration.TotalMilliseconds:0} ms。";
                StatusBrush = UiBrushes.Green;
            }
            else if (StatusMessage is "正在初始化…" or "正在刷新…" or "就绪")
            {
                StatusMessage = "就绪";
                StatusBrush = UiBrushes.Green;
            }
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
            // Window is closing.
        }
        catch (Exception ex)
        {
            _log.Error("UI", "刷新数据失败", ex);
            LastErrorMessage = "刷新失败：" + ex.Message;
            HasInitialLoadError = _snapshot is null;
            StatusMessage = LastErrorMessage;
            StatusBrush = UiBrushes.Red;
            MonitorStatusText = "刷新失败";
            MonitorStatusBrush = UiBrushes.Red;
            HasWarnings = true;
            WarningText = "数据刷新失败：" + ex.Message;
            WarningTooltip = ex.ToString();
            WarningForeground = UiBrushes.Red;
        }
        finally
        {
            IsRefreshing = false;
            BusyText = string.Empty;
            UpdateMonitorStatus();
            _refreshGate.Release();
        }
    }

    public async Task<UiOperationOutcome> ExecuteOperationAsync(
        IReadOnlyList<ElevatedAction> actions,
        string operationLabel,
        CancellationToken cancellationToken = default)
    {
        if (actions.Count == 0)
            return new UiOperationOutcome { Summary = "没有可执行的操作项。", Error = "没有可执行的操作项。" };
        if (IsBusy)
        {
            StatusMessage = "当前正在刷新或等待另一个操作，请稍后重试。";
            StatusBrush = UiBrushes.Orange;
            return new UiOperationOutcome { Summary = "当前正忙，未执行操作。", Error = "当前正忙，未执行操作。" };
        }

        IsBusyOperation = true;
        BusyText = "正在等待管理员授权并执行操作…";
        StatusMessage = "正在请求管理员授权…";
        StatusBrush = UiBrushes.Blue;
        LastOperationSummary = operationLabel + "：执行中…";
        LastOperationBrush = UiBrushes.Blue;
        try
        {
            var outcome = await _operationService.ExecuteAsync(actions, operationLabel, cancellationToken).ConfigureAwait(true);
            LastOperationSummary = operationLabel + "：" + FirstLine(outcome.Summary);
            LastOperationBrush = UiBrushes.ForOutcome(outcome.Outcome);
            StatusMessage = LastOperationSummary;
            StatusBrush = LastOperationBrush;
            if (outcome.AnyFailure || outcome.UserCancelled)
                LastErrorMessage = FirstLine(outcome.Summary);
            return outcome;
        }
        catch (OperationCanceledException)
        {
            LastOperationSummary = operationLabel + "：已取消等待";
            LastOperationBrush = UiBrushes.Orange;
            StatusMessage = "已停止等待操作结果。";
            StatusBrush = UiBrushes.Orange;
            return new UiOperationOutcome { Summary = "已停止等待操作结果。辅助进程可能仍在运行，请刷新核实。", Error = "已取消等待。" };
        }
        catch (Exception ex)
        {
            _log.Error("UI", "执行操作失败", ex);
            LastOperationSummary = operationLabel + "：失败";
            LastOperationBrush = UiBrushes.Red;
            StatusMessage = "操作失败：" + ex.Message;
            StatusBrush = UiBrushes.Red;
            LastErrorMessage = ex.Message;
            return new UiOperationOutcome { Summary = "操作失败：" + ex.Message, Error = ex.Message };
        }
        finally
        {
            IsBusyOperation = false;
            BusyText = string.Empty;
            try
            {
                await RefreshAsync().ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                _log.Error("UI", "操作后刷新失败", ex);
            }
        }
    }

    public void ReportStatus(string message, Brush brush)
    {
        StatusMessage = message;
        StatusBrush = brush;
    }

    public void OpenSelectedPathInExplorer()
    {
        var path = SelectedPath;
        if (string.IsNullOrWhiteSpace(path))
            return;
        try
        {
            if (File.Exists(path))
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    UseShellExecute = true
                };
                psi.ArgumentList.Add("/select," + path);
                System.Diagnostics.Process.Start(psi);
            }
            else
            {
                var directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
                {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        UseShellExecute = true
                    };
                    psi.ArgumentList.Add(directory);
                    System.Diagnostics.Process.Start(psi);
                }
                else
                {
                    ReportStatus("目标路径当前不存在，无法在资源管理器中定位。", UiBrushes.Orange);
                }
            }
        }
        catch (Exception ex)
        {
            _log.Error("UI", "打开资源管理器失败", ex);
            ReportStatus("无法打开资源管理器：" + ex.Message, UiBrushes.Red);
        }
    }

    public string BuildSelectedDetailsText()
    {
        return string.Join(Environment.NewLine,
            SelectionTitle,
            SelectionSubtitle,
            SelectionLine1,
            SelectionLine2,
            SelectionLine3,
            SelectionLine4);
    }

    private ListCollectionView CreateProcessView(ObservableCollection<ProcessRowViewModel> source, Predicate<object> filter)
    {
        var view = new ListCollectionView(source) { Filter = filter };
        view.SortDescriptions.Add(new SortDescription(nameof(ProcessRowViewModel.DisplayName), ListSortDirection.Ascending));
        view.SortDescriptions.Add(new SortDescription(nameof(ProcessRowViewModel.Pid), ListSortDirection.Ascending));
        return view;
    }

    private void ApplySnapshot(UiMonitorSnapshot snapshot)
    {
        var networkReadable = snapshot.NetworkResult.Error is null;
        var summaries = NetworkSummaryBuilder.Build(snapshot.NetworkResult.Connections, networkReadable);
        var ownerCandidates = new Dictionary<int, ProcessRowViewModel>();
        _policyEvaluator = new UiPolicyEvaluator(snapshot.State, snapshot.Firewall, DateTimeOffset.UtcNow);

        var desiredAppKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredSystemKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var newRows = new Dictionary<string, ProcessRowViewModel>(StringComparer.OrdinalIgnoreCase);

        foreach (var process in snapshot.ProcessResult.Processes)
        {
            var key = ProcessRowViewModel.MakeKey(process);
            _processRows.TryGetValue(key, out var row);
            if (row is null) row = new ProcessRowViewModel(process);
            var connections = summaries.TryGetValue(process.Pid, out var summary) ? summary : new ProcessNetworkSummary { Known = networkReadable };
            var policy = _policyEvaluator.EvaluateProgram(process.ExecutablePath, connections.Connections);
            row.Update(process, connections, policy);
            newRows[key] = row;
            ownerCandidates[process.Pid] = row;
            if (row.IsSystem) desiredSystemKeys.Add(key);
            else desiredAppKeys.Add(key);
        }

        RemoveRowsNotDesired(AppProcesses, desiredAppKeys);
        RemoveRowsNotDesired(SystemProcesses, desiredSystemKeys);
        foreach (var pair in newRows)
        {
            var row = pair.Value;
            if (row.IsSystem)
            {
                if (!desiredAppKeys.Contains(pair.Key)) RemoveFromCollection(AppProcesses, row);
                if (!SystemProcesses.Contains(row)) SystemProcesses.Add(row);
            }
            else
            {
                if (!desiredSystemKeys.Contains(pair.Key)) RemoveFromCollection(SystemProcesses, row);
                if (!AppProcesses.Contains(row)) AppProcesses.Add(row);
            }
        }
        _processRows.Clear();
        foreach (var pair in newRows) _processRows[pair.Key] = pair.Value;

        var connectionDesired = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var newConnectionRows = new Dictionary<string, ConnectionRowViewModel>(StringComparer.OrdinalIgnoreCase);
        foreach (var connection in snapshot.NetworkResult.Connections)
        {
            _connectionRows.TryGetValue(connection.ConnectionId, out var row);
            if (row is null) row = new ConnectionRowViewModel(connection);
            ProcessRowViewModel? owner = null;
            if (connection.ProcessResolved)
                ownerCandidates.TryGetValue(connection.OwningPid, out owner);
            var policy = _policyEvaluator.EvaluateConnection(connection);
            row.Update(connection, owner, policy, snapshot.Firewall.Availability.CanReadRules);
            newConnectionRows[connection.ConnectionId] = row;
            connectionDesired.Add(connection.ConnectionId);
        }
        RemoveConnectionRowsNotDesired(connectionDesired);
        foreach (var pair in newConnectionRows)
        {
            if (!Connections.Contains(pair.Value)) Connections.Add(pair.Value);
        }
        _connectionRows.Clear();
        foreach (var pair in newConnectionRows) _connectionRows[pair.Key] = pair.Value;

        if (IsFilterActive(_appProcessSearch, _appProcessFilterKey)) AppProcessView.Refresh();
        if (IsFilterActive(_systemProcessSearch, _systemProcessFilterKey)) SystemProcessView.Refresh();
        if (IsFilterActive(_connectionSearch, _connectionFilterKey)) ConnectionView.Refresh();

        UpdatePaneCounts();
        UpdateFirewallHeader(snapshot);
        UpdateWarningBar(snapshot);
        UpdatePendingTasks(snapshot.State);
        PruneSelection();
        RefreshSelectionDetails();
        RaiseHeaderProperties();
        if (!_loggedStartupSummary)
        {
            _loggedStartupSummary = true;
            _log.Info("UI",
                $"首次刷新：进程 {snapshot.ProcessResult.Processes.Count}（应用 {AppProcesses.Count}，系统 {SystemProcesses.Count}），连接 {snapshot.NetworkResult.Connections.Count}（未知进程 {snapshot.NetworkResult.UnknownProcessCount}），" +
                $"防火墙 {snapshot.FirewallAvailability.StatusText}，登记规则 {snapshot.State.Rules.Count}，任务 {snapshot.State.Tasks.Count}，警告 {snapshot.Warnings.Count}。");
        }
    }

    private static void RemoveRowsNotDesired(ObservableCollection<ProcessRowViewModel> collection, HashSet<string> desired)
    {
        for (var i = collection.Count - 1; i >= 0; i--)
        {
            if (!desired.Contains(collection[i].Key))
                collection.RemoveAt(i);
        }
    }

    private static void RemoveFromCollection(ObservableCollection<ProcessRowViewModel> collection, ProcessRowViewModel row)
    {
        var index = collection.IndexOf(row);
        if (index >= 0) collection.RemoveAt(index);
    }

    private void RemoveConnectionRowsNotDesired(HashSet<string> desired)
    {
        for (var i = Connections.Count - 1; i >= 0; i--)
        {
            if (!desired.Contains(Connections[i].Key))
                Connections.RemoveAt(i);
        }
    }

    private void UpdatePaneCounts()
    {
        AppProcessCountText = AppProcesses.Count.ToString();
        SystemProcessCountText = SystemProcesses.Count.ToString();
        ConnectionCountText = Connections.Count.ToString();
        AppProcessVisibleText = $"显示 {AppProcessView.Cast<object>().Count()} / {AppProcesses.Count}";
        SystemProcessVisibleText = $"显示 {SystemProcessView.Cast<object>().Count()} / {SystemProcesses.Count}";
        ConnectionVisibleText = $"显示 {ConnectionView.Cast<object>().Count()} / {Connections.Count}";
    }

    private void UpdateFirewallHeader(UiMonitorSnapshot snapshot)
    {
        var availability = snapshot.FirewallAvailability;
        FirewallError = availability.Error;
        var ruleCount = snapshot.State.Rules.Count(r => r.Status == ManagedRuleStatus.Active);
        var prefixCount = availability.ManagedRuleCount ?? ruleCount;
        if (availability.IsAccessLimited)
        {
            FirewallStatusText = "读取受限（需 UAC 核对）";
            FirewallDetailText = $"实际规则状态未知 · 本工具登记规则 {ruleCount} 条";
            FirewallStatusBrush = UiBrushes.Orange;
        }
        else
        {
            FirewallStatusText = availability.StatusText;
            FirewallDetailText = $"{availability.ProfilesSummary} · 本工具防火墙规则 {prefixCount} 条";
            FirewallStatusBrush = !availability.IsAvailable || !availability.CanReadRules
                ? UiBrushes.Red
                : !availability.IsCurrentProfileProtected ? UiBrushes.Orange : UiBrushes.Green;
        }
    }

    private void UpdateWarningBar(UiMonitorSnapshot snapshot)
    {
        var warnings = new List<string>(snapshot.Warnings);
        if (!string.IsNullOrWhiteSpace(_startupNotice)) warnings.Add(_startupNotice);
        if (!string.IsNullOrWhiteSpace(_settingsWarning)) warnings.Add(_settingsWarning);
        var st = snapshot.State.Tasks;
        var runningStale = st.Count(t => t.Status == ScheduledTaskStatus.Running && t.StartedUtc is { } s && DateTimeOffset.UtcNow - s > TimeSpan.FromMinutes(10));
        var unknownFirewall = !snapshot.FirewallAvailability.CanReadRules;
        var serious = snapshot.ProcessResult.Error is not null || snapshot.NetworkResult.Error is not null ||
                       snapshot.StateError is not null ||
                       (!snapshot.FirewallAvailability.IsAvailable && !snapshot.FirewallAvailability.IsAccessLimited) ||
                       runningStale > 0;
        HasWarnings = warnings.Count > 0;
        WarningText = warnings.Count == 0
            ? string.Empty
            : string.Join("  ·  ", warnings.Take(3)) + (warnings.Count > 3 ? $"  ·  另有 {warnings.Count - 3} 项提示" : string.Empty);
        WarningTooltip = string.Join(Environment.NewLine, warnings);
        WarningForeground = serious ? UiBrushes.Red : UiBrushes.Orange;
    }

    private void UpdatePendingTasks(AppState state)
    {
        var now = DateTimeOffset.UtcNow;
        var pending = state.Tasks.Count(t => t.Status == ScheduledTaskStatus.Pending);
        var running = state.Tasks.Count(t => t.Status == ScheduledTaskStatus.Running);
        var overdue = state.Tasks.Count(t => t.Status == ScheduledTaskStatus.Pending && t.PlannedUtc.AddMinutes(2) < now);
        PendingTaskCount = pending;
        PendingTaskText = $"待执行任务 {pending}" +
                          (running > 0 ? $" · 执行中 {running}" : string.Empty) +
                          (overdue > 0 ? $" · 超时 {overdue}" : string.Empty);
        UpdateMonitorStatus();
    }

    private void UpdateMonitorStatus()
    {
        if (IsRefreshing)
        {
            MonitorStatusText = "正在刷新…";
            MonitorStatusBrush = UiBrushes.Blue;
            return;
        }
        if (!_initialized)
        {
            MonitorStatusText = "尚未启动";
            MonitorStatusBrush = UiBrushes.Gray;
            return;
        }
        if (_snapshot?.ProcessResult.Error is not null || _snapshot?.NetworkResult.Error is not null)
        {
            MonitorStatusText = "监控部分失败";
            MonitorStatusBrush = UiBrushes.Red;
            return;
        }
        if (!_settings.AutoRefreshEnabled)
        {
            MonitorStatusText = "自动刷新已暂停";
            MonitorStatusBrush = UiBrushes.Gray;
            return;
        }
        MonitorStatusText = $"监控中 · 每 {_settings.RefreshIntervalSeconds} 秒";
        MonitorStatusBrush = UiBrushes.Green;
    }

    private void RaiseHeaderProperties()
    {
        OnPropertyChanged(nameof(IsElevated));
        OnPropertyChanged(nameof(PrivilegeStatusText));
        OnPropertyChanged(nameof(CanCancelTasks));
        OnPropertyChanged(nameof(HasWarnings));
        OnPropertyChanged(nameof(PendingTaskCount));
        OnPropertyChanged(nameof(SelectedCountText));
    }

    private void OnTimerTick(object? sender, EventArgs e)
    {
        if (_disposed || IsBusyOperation || !_settings.AutoRefreshEnabled) return;
        _ = RefreshAsync(manual: false);
    }

    private void ConfigureTimer()
    {
        _timer.Stop();
        _timer.Interval = TimeSpan.FromSeconds(_settings.RefreshIntervalSeconds);
        if (_initialized && _settings.AutoRefreshEnabled)
            _timer.Start();
        UpdateMonitorStatus();
    }

    private bool FilterAppProcess(object item)
    {
        if (item is not ProcessRowViewModel row) return false;
        if (!row.MatchesSearch(_appProcessSearch)) return false;
        return _appProcessFilterKey switch
        {
            "network" => row.ConnectionCount > 0 || row.ActiveConnectionCount > 0,
            "blocked" => row.HasActiveRule || row.HasManagedActiveRule,
            "tasks" => row.HasPendingTask,
            "issues" => row.HasFailure || row.HasInconsistentRule || row.HasUnknownRule,
            _ => true
        };
    }

    private bool FilterSystemProcess(object item)
    {
        if (item is not ProcessRowViewModel row || !row.IsSystem) return false;
        if (!row.MatchesSearch(_systemProcessSearch)) return false;
        return _systemProcessFilterKey switch
        {
            "network" => row.ConnectionCount > 0 || row.ActiveConnectionCount > 0,
            "blocked" => row.HasActiveRule || row.HasManagedActiveRule,
            "tasks" => row.HasPendingTask,
            "issues" => row.HasFailure || row.HasInconsistentRule || row.HasUnknownRule,
            "critical" => row.IsCritical,
            _ => true
        };
    }

    private bool FilterConnection(object item)
    {
        if (item is not ConnectionRowViewModel row) return false;
        if (!row.MatchesSearch(_connectionSearch)) return false;
        return _connectionFilterKey switch
        {
            "active" => row.IsActiveConnection,
            "listening" => row.IsListening,
            "blocked" => row.HasActiveRule || row.HasManagedActiveRule,
            "tasks" => row.HasPendingTask,
            "issues" => row.HasFailure || row.HasInconsistentRule || row.HasUnknownRule,
            _ => true
        };
    }

    private static bool IsFilterActive(string search, string filterKey) =>
        !string.IsNullOrWhiteSpace(search) || !string.Equals(filterKey, "all", StringComparison.Ordinal);

    private void RefreshAppProcessFilters()
    {
        AppProcessView.Refresh();
        AppProcessVisibleText = $"显示 {AppProcessView.Cast<object>().Count()} / {AppProcesses.Count}";
    }

    private void RefreshSystemProcessFilters()
    {
        SystemProcessView.Refresh();
        SystemProcessVisibleText = $"显示 {SystemProcessView.Cast<object>().Count()} / {SystemProcesses.Count}";
    }

    private void RefreshConnectionFilters()
    {
        ConnectionView.Refresh();
        ConnectionVisibleText = $"显示 {ConnectionView.Cast<object>().Count()} / {Connections.Count}";
    }

    private void PruneSelection()
    {
        var appSet = AppProcesses.ToHashSet();
        var systemSet = SystemProcesses.ToHashSet();
        var connectionSet = Connections.ToHashSet();
        if (_selectedApp.Any(r => !appSet.Contains(r))) _selectedApp = _selectedApp.Where(appSet.Contains).ToList();
        if (_selectedSystem.Any(r => !systemSet.Contains(r))) _selectedSystem = _selectedSystem.Where(systemSet.Contains).ToList();
        if (_selectedConnections.Any(r => !connectionSet.Contains(r))) _selectedConnections = _selectedConnections.Where(connectionSet.Contains).ToList();
        if (_activeScope == SelectionScope.AppProcesses && _selectedApp.Count == 0) _activeScope = SelectionScope.None;
        if (_activeScope == SelectionScope.SystemProcesses && _selectedSystem.Count == 0) _activeScope = SelectionScope.None;
        if (_activeScope == SelectionScope.Connections && _selectedConnections.Count == 0) _activeScope = SelectionScope.None;
    }

    private void RefreshSelectionDetails()
    {
        OnPropertyChanged(nameof(ActiveSelectedProcesses));
        OnPropertyChanged(nameof(ActiveSelectedConnections));
        OnPropertyChanged(nameof(ActiveSelectedObjects));
        OnPropertyChanged(nameof(ActiveSelectionScope));
        OnPropertyChanged(nameof(HasSelection));

        if (_activeScope == SelectionScope.Connections)
        {
            RefreshConnectionSelection();
            return;
        }
        if (_activeScope is SelectionScope.AppProcesses or SelectionScope.SystemProcesses)
        {
            RefreshProcessSelection(ActiveSelectedProcesses);
            return;
        }
        SetNoSelection();
    }

    private void SetNoSelection()
    {
        SelectionTitle = "未选择对象";
        SelectionSubtitle = "在表格中选择一行或多行以查看详情并启用操作按钮。";
        SelectionLine1 = string.Empty;
        SelectionLine2 = string.Empty;
        SelectionLine3 = string.Empty;
        SelectionLine4 = string.Empty;
        SelectedCountText = "已选 0 项";
        SelectedPath = null;
        _selectionCanBlock = false;
        _selectionCanUnblock = false;
        _selectionCanSchedule = false;
        OnPropertyChanged(nameof(CanBlockSelected));
        OnPropertyChanged(nameof(CanUnblockSelected));
        OnPropertyChanged(nameof(CanScheduleSelected));
        OnPropertyChanged(nameof(CanCancelTasks));
    }

    private void RefreshProcessSelection(IReadOnlyList<ProcessRowViewModel> rows)
    {
        if (rows.Count == 0)
        {
            SetNoSelection();
            return;
        }

        _selectionCanBlock = rows.Any(r => r.CanBlockProgram);
        _selectionCanUnblock = rows.Any(r => r.MatchingRules.Any(x => x.IsActiveRecord && x.Record.TargetKind == RuleTargetKind.Program));
        _selectionCanSchedule = _selectionCanBlock;
        OnPropertyChanged(nameof(CanBlockSelected));
        OnPropertyChanged(nameof(CanUnblockSelected));
        OnPropertyChanged(nameof(CanScheduleSelected));
        SelectedCountText = $"已选 {rows.Count} 个进程";

        if (rows.Count == 1)
        {
            var row = rows[0];
            SelectionTitle = $"{row.DisplayName}  ·  PID {row.PidText}";
            SelectionSubtitle = row.PathDisplay;
            SelectionLine1 = $"会话 {row.SessionText} · 发布者 {row.PublisherText} · 网络 {row.NetworkStatusText} · 连接 {row.ConnectionCountText}";
            SelectionLine2 = $"策略：{row.PolicyText}";
            SelectionLine3 = $"分类 {row.CategoryText} · 风险 {row.RiskSummary}" + (row.PendingTaskCount > 0 ? $" · 待执行任务 {row.PendingTaskCount}" : string.Empty);
            SelectionLine4 = row.Notes;
            SelectedPath = row.ExecutablePath;
        }
        else
        {
            var blocked = rows.Count(r => r.HasActiveRule);
            var tasks = rows.Count(r => r.HasPendingTask);
            var protectedCount = rows.Count(r => r.IsProgramBlockProtected);
            SelectionTitle = $"已选择 {rows.Count} 个进程";
            SelectionSubtitle = string.Join("，", rows.Take(4).Select(r => $"{r.DisplayName} (PID {r.PidText})")) + (rows.Count > 4 ? " 等" : string.Empty);
            SelectionLine1 = $"已禁止 {blocked} 项 · 有待执行任务 {tasks} 项 · 受保护不可阻断 {protectedCount} 项";
            SelectionLine2 = "批量操作会逐项校验；受保护对象会被列为跳过，不会整体报成功。";
            SelectionLine3 = string.Empty;
            SelectionLine4 = "确认对话框会再次显示每个程序和路径；同一可执行文件的规则会影响其全部实例。";
            SelectedPath = null;
        }
    }

    private void RefreshConnectionSelection()
    {
        var rows = _selectedConnections;
        if (rows.Count == 0)
        {
            SetNoSelection();
            return;
        }

        _selectionCanBlock = rows.Any(r => r.CanBlockProgram || r.CanBlockRemote);
        _selectionCanUnblock = rows.Any(r => r.HasManagedActiveRule);
        _selectionCanSchedule = rows.Any(r => r.CanBlockProgram || r.CanBlockRemote);
        OnPropertyChanged(nameof(CanBlockSelected));
        OnPropertyChanged(nameof(CanUnblockSelected));
        OnPropertyChanged(nameof(CanScheduleSelected));
        SelectedCountText = $"已选 {rows.Count} 条连接";

        if (rows.Count == 1)
        {
            var row = rows[0];
            SelectionTitle = $"{row.ProcessDisplayName}  ·  PID {row.PidText}  ·  {row.ProtocolDetail}";
            SelectionSubtitle = $"{row.LocalEndpoint}  →  {row.RemoteEndpoint}";
            SelectionLine1 = $"状态 {row.ActivityText} · 所属进程路径 {row.PathDisplay}";
            SelectionLine2 = $"策略：{row.PolicyText}";
            SelectionLine3 = row.Notes;
            SelectionLine4 = $"TCP 状态：{row.TcpStateText} · 防火墙规则会作用于规则目标，已有连接可能短暂保持。";
            SelectedPath = row.ProcessPath;
        }
        else
        {
            var blocked = rows.Count(r => r.HasActiveRule);
            var unknown = rows.Count(r => !r.ProcessResolved);
            SelectionTitle = $"已选择 {rows.Count} 条网络连接";
            SelectionSubtitle = "可在“立即禁止”或“延迟禁止/解除”中选择按程序路径或远程 IP 目标建立规则。";
            SelectionLine1 = $"已禁止 {blocked} 条 · 未知进程 {unknown} 条";
            SelectionLine2 = "按远程地址建立的规则会影响所有访问该地址的应用程序，而不只当前进程。";
            SelectionLine3 = string.Empty;
            SelectionLine4 = "连接快照来自系统 TCP/UDP 表；无法关联 PID 的连接不会被归到虚构进程。";
            SelectedPath = null;
        }
    }

    public void FocusSelectionScope(SelectionScope scope)
    {
        if (scope == SelectionScope.None)
        {
            _activeScope = SelectionScope.None;
            RefreshSelectionDetails();
            return;
        }

        _activeScope = scope;
        RefreshSelectionDetails();
    }

    private static string FirstLine(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "未提供结果";
        var line = text.Split('\n', 2)[0].Trim();
        return line.Length > 160 ? line[..160] + "…" : line;
    }

    private static string GetVersionText()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
            return informational.Split('+')[0];
        return assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    }

    private string _settingsWarning = string.Empty;

    private void AppendStartupWarning(string message)
    {
        _settingsWarning = message;
        if (_settingsWarning.Length > 0) _startupNotice = message;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _timer.Stop();
        _disposeCts.Cancel();
        _disposeCts.Dispose();
        _refreshGate.Dispose();
    }
}
