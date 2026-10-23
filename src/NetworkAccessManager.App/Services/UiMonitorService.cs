using System.Diagnostics;
using System.Windows.Media;
using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.App.ViewModels;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Firewall;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Services;

namespace NetworkAccessManager.App.Services;

public sealed class UiMonitorSnapshot
{
    public ProcessCollectionResult ProcessResult { get; init; } = new();
    public NetworkCollectionResult NetworkResult { get; init; } = new();
    public AppState State { get; init; } = new();
    public StoreReadResult? StoreRead { get; init; }
    public string? StateError { get; init; }
    public FirewallInspectionBatch Firewall { get; init; } = new();
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    public DateTimeOffset CapturedUtc { get; init; }
    public TimeSpan Duration { get; init; }
    public bool ProcessReadOk => ProcessResult.Error is null;
    public bool NetworkReadOk => NetworkResult.Error is null;
    public bool StateReadOk => StateError is null;
    public FirewallAvailability FirewallAvailability => Firewall.Availability;
}

public sealed class UiMonitorService
{
    private readonly AppPaths _paths;
    private readonly IAppLog _log;
    private readonly StateRepository _store;
    private readonly ComFirewallManager _firewall;
    private readonly ProcessSnapshotService _processes;
    private readonly NetworkConnectionService _network;

    public UiMonitorService(AppPaths paths, IAppLog log)
    {
        _paths = paths;
        _log = log;
        _store = new StateRepository(paths);
        _firewall = new ComFirewallManager();
        _processes = new ProcessSnapshotService(log);
        _network = new NetworkConnectionService(log);
    }

    public Task<UiMonitorSnapshot> CaptureAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => Capture(cancellationToken), cancellationToken);

    private UiMonitorSnapshot Capture(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var warnings = new List<string>();
        cancellationToken.ThrowIfCancellationRequested();

        var ownExecutable = Environment.ProcessPath;
        var processResult = _processes.Capture(ownExecutable);
        if (!string.IsNullOrWhiteSpace(processResult.Error))
            warnings.Add(processResult.Error!);
        warnings.AddRange(processResult.Warnings.Take(4));
        cancellationToken.ThrowIfCancellationRequested();

        var networkResult = _network.Capture(processResult.Processes);
        if (!string.IsNullOrWhiteSpace(networkResult.Error))
            warnings.Add(networkResult.Error!);
        warnings.AddRange(networkResult.Warnings.Take(4));
        cancellationToken.ThrowIfCancellationRequested();

        StoreReadResult? storeRead = null;
        string? stateError = null;
        var state = new AppState();
        try
        {
            storeRead = _store.ReadState();
            state = storeRead.State;
            if (storeRead.Warning is not null)
                warnings.Add(storeRead.Warning);
        }
        catch (Exception ex)
        {
            stateError = ex.Message;
            warnings.Add("状态数据读取失败：" + ex.Message);
            _log.Error("Monitor", "读取状态数据失败", ex);
        }

        var activeRules = state.Rules.Where(r => r.Status == ManagedRuleStatus.Active).ToList();
        FirewallInspectionBatch firewallBatch;
        try
        {
            if (activeRules.Count > 0)
            {
                firewallBatch = _firewall.InspectRules(activeRules);
            }
            else
            {
                var availability = _firewall.GetAvailability();
                firewallBatch = new FirewallInspectionBatch
                {
                    Availability = availability,
                    Inspections = new Dictionary<string, FirewallRuleInspection>(StringComparer.OrdinalIgnoreCase),
                    CheckedUtc = DateTimeOffset.UtcNow
                };
            }
        }
        catch (Exception ex)
        {
            _log.Error("Monitor", "读取 Windows 防火墙状态失败", ex);
            var availability = new FirewallAvailability
            {
                IsAvailable = false,
                CanReadRules = false,
                IsCurrentProfileProtected = false,
                StatusText = "读取失败",
                Error = ex.Message,
                ProfilesSummary = "未知"
            };
            var inspections = activeRules.ToDictionary(
                r => r.RuleId,
                r => new FirewallRuleInspection
                {
                    RuleId = r.RuleId,
                    FirewallRuleName = r.FirewallRuleName,
                    State = RuleInspectionState.Unknown,
                    Detail = "读取 Windows 防火墙失败：" + ex.Message
                },
                StringComparer.OrdinalIgnoreCase);
            firewallBatch = new FirewallInspectionBatch
            {
                Availability = availability,
                Inspections = inspections,
                CheckedUtc = DateTimeOffset.UtcNow
            };
        }

        if (!string.IsNullOrWhiteSpace(firewallBatch.Availability.Error))
        {
            if (!firewallBatch.Availability.IsAccessLimited)
                warnings.Add("Windows 防火墙：" + firewallBatch.Availability.Error);
        }
        if (firewallBatch.Availability.IsAccessLimited)
        {
            warnings.Add("当前界面无法读取 Windows 防火墙规则（权限不足）。规则实际状态显示为“未知”；修改规则时会通过 UAC 请求管理员授权，并由辅助进程重新核对。");
        }
        else if (!firewallBatch.Availability.IsAvailable)
        {
            warnings.Add("Windows 防火墙不可用或状态读取失败：" + (firewallBatch.Availability.Error ?? firewallBatch.Availability.StatusText));
        }
        else if (!firewallBatch.Availability.CanReadRules)
        {
            warnings.Add("当前无法读取 Windows 防火墙规则，规则状态显示为未知。");
        }
        if (firewallBatch.Availability.IsAvailable && !firewallBatch.Availability.IsCurrentProfileProtected)
            warnings.Add("当前网络配置文件的 Windows 防火墙未启用，阻断规则无法保证生效。本工具不会修改全局防火墙开关。");

        var inconsistent = activeRules.Count(r => firewallBatch.Inspections.TryGetValue(r.RuleId, out var i) &&
                                                  i.State is RuleInspectionState.Missing or RuleInspectionState.Mismatched);
        if (inconsistent > 0)
            warnings.Add($"检测到 {inconsistent} 条本工具规则已被外部删除或修改，相关状态显示为不一致。");
        var pendingOverdue = state.Tasks.Count(t =>
            t.Status == ScheduledTaskStatus.Pending && t.PlannedUtc.AddMinutes(2) < DateTimeOffset.UtcNow);
        if (pendingOverdue > 0)
            warnings.Add($"{pendingOverdue} 个定时任务已超过预定时间仍未记录执行结果；Windows 可能在恢复/登录后补执行，请勿误认为已经完成。");
        var staleRunning = state.Tasks.Count(t =>
            t.Status == ScheduledTaskStatus.Running && t.StartedUtc is { } started && DateTimeOffset.UtcNow - started > TimeSpan.FromMinutes(10));
        if (staleRunning > 0)
            warnings.Add($"{staleRunning} 个任务停留在“执行中”超过 10 分钟，可能因中断而未完成，请检查历史记录。");
        var unknownProcesses = networkResult.UnknownProcessCount;
        if (unknownProcesses > 0)
            warnings.Add($"{unknownProcesses} 个网络端点的 PID 未能关联到已读取的进程，已标记为“未知进程”。");

        stopwatch.Stop();
        return new UiMonitorSnapshot
        {
            ProcessResult = processResult,
            NetworkResult = networkResult,
            State = state,
            StoreRead = storeRead,
            StateError = stateError,
            Firewall = firewallBatch,
            Warnings = warnings.Distinct().ToList(),
            CapturedUtc = DateTimeOffset.UtcNow,
            Duration = stopwatch.Elapsed
        };
    }
}

public static class NetworkSummaryBuilder
{
    public static IReadOnlyDictionary<int, ProcessNetworkSummary> Build(
        IReadOnlyList<NetworkConnectionRecord> connections,
        bool networkReadable)
    {
        var map = new Dictionary<int, List<NetworkConnectionRecord>>();
        foreach (var connection in connections)
        {
            if (!map.TryGetValue(connection.OwningPid, out var list))
            {
                list = new List<NetworkConnectionRecord>();
                map[connection.OwningPid] = list;
            }
            list.Add(connection);
        }

        var result = new Dictionary<int, ProcessNetworkSummary>();
        foreach (var pair in map)
        {
            var list = pair.Value;
            var active = list.Count(c => c.ActivityLevel == NetworkActivityLevel.Active);
            var listening = list.Count(c => c.Protocol == NetworkProtocol.Tcp && c.IsListening);
            var udp = list.Count(c => c.Protocol == NetworkProtocol.Udp);
            var level = active > 0
                ? NetworkActivityLevel.Active
                : list.Count > 0 ? NetworkActivityLevel.Listening : NetworkActivityLevel.None;
            result[pair.Key] = new ProcessNetworkSummary
            {
                Known = networkReadable,
                EndpointCount = list.Count,
                ActiveTcpCount = active,
                ListeningCount = listening,
                UdpCount = udp,
                Level = networkReadable ? level : NetworkActivityLevel.None,
                Connections = list.OrderBy(c => c.Protocol).ThenBy(c => c.LocalPort).ToList()
            };
        }
        return result;
    }
}
