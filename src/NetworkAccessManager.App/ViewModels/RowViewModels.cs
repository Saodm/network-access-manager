using System.Windows.Media;
using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.ViewModels;

public sealed class ProcessNetworkSummary
{
    public bool Known { get; init; }
    public int EndpointCount { get; init; }
    public int ActiveTcpCount { get; init; }
    public int ListeningCount { get; init; }
    public int UdpCount { get; init; }
    public NetworkActivityLevel Level { get; init; }
    public IReadOnlyList<NetworkConnectionRecord> Connections { get; init; } = Array.Empty<NetworkConnectionRecord>();
}

public sealed class ProcessRowViewModel : ObservableObject
{
    private ProcessRecord _record;
    private TargetPolicyView _policy = new();
    private ProcessNetworkSummary _network = new() { Known = true };

    public ProcessRowViewModel(ProcessRecord record)
    {
        _record = record;
        Key = MakeKey(record);
    }

    public string Key { get; private set; }
    public ProcessRecord Record => _record;
    public int Pid => _record.Pid;
    public string PidText => _record.Pid.ToString();
    public string ProcessName => _record.Name;
    public string DisplayName => _record.DisplayName;
    public string? ExecutablePath => _record.ExecutablePath;
    public string PathDisplay => string.IsNullOrWhiteSpace(_record.ExecutablePath) ? "未知" : _record.ExecutablePath!;
    public string PathToolTip => string.IsNullOrWhiteSpace(_record.ExecutablePath)
        ? _record.ModuleQueryError ?? "无法读取可执行文件路径"
        : _record.ExecutablePath!;
    public string CategoryText => _record.CategoryText;
    public string SessionText => _record.SessionId >= 0 ? _record.SessionId.ToString() : "未知";
    public string StartTimeText => _record.StartTimeUtc is null ? "未知" : _record.StartTimeUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string ServiceSummary => _record.ServiceSummary;
    public string ClassificationEvidence => _record.ClassificationEvidence;
    public string SignatureStatusText => _record.Signature.StatusText;
    public string PublisherText => BuildPublisherText(_record);
    public string CompanyText => _record.CompanyName ?? "未知";
    public string FileVersionText => _record.FileVersion ?? "未知";
    public string RiskSummary => _record.RiskSummary;
    public RiskLevel Risk => _record.Risk;
    public Brush RiskBrush => UiBrushes.ForRisk(_record.Risk);
    public Brush RiskBackground => UiBrushes.BackgroundForRisk(_record.Risk);
    public bool IsSystem => _record.Category != ProcessCategory.UserApplication;
    public bool IsCritical => _record.Category == ProcessCategory.SystemCritical;
    public bool IsProgramBlockProtected => _record.IsProgramBlockProtected;
    public string ProtectionReason => _record.ProtectionReason;
    public bool CanBlockProgram => _record.NormalizedPath is not null && !_record.IsProgramBlockProtected;
    public string BlockUnavailableReason => _record.NormalizedPath is null
        ? "没有可读取的可执行文件路径，不能建立程序路径规则。可以改用网络目标规则。"
        : _record.ProtectionReason.Length > 0
            ? _record.ProtectionReason
            : "此对象当前不可建立程序规则。";
    public bool RequiresHighRiskAck => _record.Risk >= RiskLevel.High && CanBlockProgram;
    public string TargetValue => _record.ExecutablePath ?? string.Empty;
    public RuleTargetKind TargetKind => RuleTargetKind.Program;

    public bool NetworkKnown => _network.Known;
    public int ConnectionCount => _network.EndpointCount;
    public int ActiveConnectionCount => _network.ActiveTcpCount;
    public int ListeningCount => _network.ListeningCount;
    public int UdpCount => _network.UdpCount;
    public string ConnectionCountText => !_network.Known ? "未知" : _network.ActiveTcpCount > 0
        ? $"{_network.ActiveTcpCount} 活动 / {_network.EndpointCount} 总数"
        : _network.EndpointCount.ToString();
    public string NetworkStatusText => !_network.Known
        ? "未知"
        : _network.ActiveTcpCount > 0
            ? "活动中"
            : _network.EndpointCount > 0 ? "监听/端点" : "无连接";
    public NetworkActivityLevel NetworkLevel => _network.Known ? _network.Level : NetworkActivityLevel.None;
    public Brush NetworkStatusBrush => !_network.Known ? UiBrushes.Orange : UiBrushes.ForNetwork(_network.Level, _network.EndpointCount > 0);
    public IReadOnlyList<NetworkConnectionRecord> Connections => _network.Connections;
    public string StateText => "运行中";
    public Brush StateBrush => UiBrushes.Green;

    public string PolicyText => _policy.Text;
    public string PolicyDetail => _policy.Detail;
    public PolicyStateKind PolicyKind => _policy.Kind;
    public Brush PolicyBrush => _policy.Brush;
    public Brush PolicyBackground => UiBrushes.BackgroundForPolicy(_policy.Kind);
    public bool HasActiveRule => _policy.HasActiveVerifiedRule;
    public bool HasManagedActiveRule => _policy.HasManagedActiveRule;
    public bool HasPendingTask => _policy.HasPendingTask;
    public bool HasFailure => _policy.HasFailure;
    public bool HasInconsistentRule => _policy.HasInconsistentRule;
    public bool HasUnknownRule => _policy.HasUnknownRule;
    public bool HasTasks => _policy.MatchingTasks.Count > 0;
    public int PendingTaskCount => _policy.PendingTaskCount;
    public int ActiveRuleCount => _policy.ActiveRuleCount;
    public BlockDirections ActiveDirections => _policy.ProgramRuleDirections;
    public IReadOnlyList<RuleStatusView> MatchingRules => _policy.MatchingRules;
    public IReadOnlyList<ScheduledTaskView> MatchingTasks => _policy.MatchingTasks;
    public string TaskSummary => _policy.NextTaskSummary ?? "—";
    public DateTimeOffset? NextAutoUnblockUtc => _policy.NextAutoUnblockUtc;

    public string Notes
    {
        get
        {
            if (_record.IsProgramBlockProtected) return _record.ProtectionReason;
            if (_record.NormalizedPath is null) return "路径未知，不能按程序建立规则。";
            if (_policy.TargetRuleImpactCount > 0) return $"有 {_policy.TargetRuleImpactCount} 个连接命中已生效的网络目标规则。";
            if (_record.Category == ProcessCategory.Unknown) return _record.ClassificationEvidence;
            return "程序规则按可执行文件路径生效，可能影响同一程序的全部实例。";
        }
    }

    public string SearchText => string.Join(' ',
        PidText, ProcessName, DisplayName, PathDisplay, PublisherText, SignatureStatusText, CategoryText,
        SessionText, ServiceSummary, NetworkStatusText, PolicyText, RiskSummary, Notes);

    public void Update(ProcessRecord record, ProcessNetworkSummary network, TargetPolicyView policy)
    {
        if (!string.Equals(Key, MakeKey(record), StringComparison.Ordinal))
            Key = MakeKey(record);
        _record = record;
        _network = network;
        _policy = policy;
        RaiseAllPropertiesChanged();
    }

    public void UpdatePolicyOnly(TargetPolicyView policy)
    {
        _policy = policy;
        RaiseAllPropertiesChanged();
    }

    public static string MakeKey(ProcessRecord record)
    {
        var start = record.StartTimeUtc?.UtcTicks.ToString() ?? "?";
        var path = record.ExecutablePath ?? string.Empty;
        return $"{record.Pid}|{start}|{path.ToLowerInvariant()}";
    }

    public bool MatchesSearch(string search)
    {
        if (string.IsNullOrWhiteSpace(search)) return true;
        return SearchText.Contains(search.Trim(), StringComparison.CurrentCultureIgnoreCase);
    }

    private static string BuildPublisherText(ProcessRecord record)
    {
        return record.Signature.State switch
        {
            SignatureState.Valid => string.IsNullOrWhiteSpace(record.Signature.Publisher)
                ? "已验证（发布者未知）"
                : $"{record.Signature.Publisher}（已验证）",
            SignatureState.NotSigned => "未验证签名",
            SignatureState.Invalid => "签名无效",
            SignatureState.Unavailable => "无法读取签名",
            _ => "签名未知"
        };
    }
}

public sealed class ConnectionRowViewModel : ObservableObject
{
    private NetworkConnectionRecord _record;
    private ProcessRowViewModel? _owner;
    private TargetPolicyView _policy = new();
    private bool _firewallReadable;

    public ConnectionRowViewModel(NetworkConnectionRecord record)
    {
        _record = record;
        Key = record.ConnectionId;
    }

    public string Key { get; }
    public NetworkConnectionRecord Record => _record;
    public ProcessRowViewModel? OwnerRow => _owner;
    public int Pid => _record.OwningPid;
    public string PidText => _record.OwningPid.ToString();
    public bool ProcessResolved => _record.ProcessResolved;
    public bool IsUnknownProcess => !_record.ProcessResolved;
    public string ProcessDisplayName => !_record.ProcessResolved ? "未知进程" : _owner?.DisplayName ?? _record.ProcessName ?? "未知进程";
    public string ProcessName => _owner?.ProcessName ?? _record.ProcessName ?? "未知";
    public string OwnerText => _record.ProcessResolved
        ? $"{ProcessDisplayName} (PID {_record.OwningPid})"
        : $"未知进程 (PID {_record.OwningPid})";
    public string? ProcessPath => _record.ProcessPath ?? _owner?.ExecutablePath;
    public string PathDisplay => string.IsNullOrWhiteSpace(ProcessPath) ? "未知" : ProcessPath!;
    public string ProtocolText => _record.ProtocolText;
    public string IpVersionText => _record.IpVersionText;
    public string ProtocolDetail => $"{_record.ProtocolText} / {_record.IpVersionText}";
    public string LocalEndpoint => _record.LocalEndpoint;
    public string RemoteEndpoint => _record.RemoteEndpoint;
    public string TcpStateText => _record.TcpStateText;
    public bool IsListening => _record.IsListening;
    public bool IsActiveConnection => _record.ActivityLevel == NetworkActivityLevel.Active;
    public string ActivityText => _record.Protocol == NetworkProtocol.Udp
        ? "UDP 端点"
        : _record.TcpStateCode switch
        {
            2 => "监听",
            3 => "正在连接",
            4 => "同步已接收",
            5 => "已连接",
            6 => "FIN 等待 1",
            7 => "FIN 等待 2",
            8 => "关闭等待",
            9 => "正在关闭",
            10 => "最后确认",
            11 => "TIME_WAIT",
            12 => "删除 TCB",
            _ => _record.TcpStateText
        };
    public Brush ActivityBrush => _record.IsListening ? UiBrushes.Blue : UiBrushes.Green;
    public string LocalPortText => _record.LocalPort.ToString();
    public string RemotePortText => _record.RemotePort?.ToString() ?? "—";
    public string? RemoteAddress => _record.RemoteAddress;
    public bool HasRemoteTarget => _record.RemotePort is > 0 && !string.IsNullOrWhiteSpace(_record.RemoteAddress);
    public bool CanBlockProgram => _owner?.CanBlockProgram == true;
    public string ProgramBlockUnavailableReason => _owner is null
        ? "无法将该连接可靠关联到进程，不能按程序建立规则。"
        : _owner.BlockUnavailableReason;
    public bool CanBlockRemote => HasRemoteTarget && NetworkTargetValidator.Validate(_record.RemoteAddress).IsValid;
    public string RemoteBlockUnavailableReason => HasRemoteTarget
        ? "远程地址无法作为单地址目标校验，不能按目标建立规则。"
        : "该连接没有可识别的远程地址（监听端点或 UDP 端点），不能按目标建立规则。";
    public bool RequiresHighRiskAck => _owner?.RequiresHighRiskAck == true;

    public string PolicyText => _policy.Text;
    public string PolicyDetail => _policy.Detail;
    public PolicyStateKind PolicyKind => _policy.Kind;
    public Brush PolicyBrush => _policy.Brush;
    public Brush PolicyBackground => UiBrushes.BackgroundForPolicy(_policy.Kind);
    public bool HasActiveRule => _policy.HasActiveVerifiedRule;
    public bool HasPendingTask => _policy.HasPendingTask;
    public bool HasFailure => _policy.HasFailure;
    public bool HasManagedActiveRule => _policy.HasManagedActiveRule;
    public bool HasInconsistentRule => _policy.HasInconsistentRule;
    public bool HasUnknownRule => _policy.HasUnknownRule;
    public BlockDirections ActiveDirections => _policy.VerifiedDirections;
    public IReadOnlyList<RuleStatusView> MatchingRules => _policy.MatchingRules;
    public IReadOnlyList<ScheduledTaskView> MatchingTasks => _policy.MatchingTasks;
    public string TaskSummary => _policy.NextTaskSummary ?? "—";

    public string Notes
    {
        get
        {
            if (!_record.ProcessResolved) return "PID 未在进程快照中找到，未关联到具体程序。";
            if (_record.Protocol == NetworkProtocol.Udp) return "UDP 端点没有可识别的远端地址；如需禁止请按所属程序建立规则。";
            if (_record.IsListening) return "监听端点没有远程目标；如需禁止请按所属程序建立规则。";
            if (_policy.HasActiveVerifiedRule) return "规则已生效；已经建立的连接可能不会立即断开。";
            if (!_firewallReadable && _policy.HasManagedActiveRule) return "无法读取防火墙规则，当前策略状态未知。";
            return "连接状态来自系统 TCP/UDP 表，PID 来自系统接口。";
        }
    }

    public string SearchText => string.Join(' ',
        ProcessDisplayName, ProcessName, PidText, ProtocolDetail, LocalEndpoint, RemoteEndpoint,
        TcpStateText, PolicyText, PathDisplay, Notes, ActivityText);

    public void Update(NetworkConnectionRecord record, ProcessRowViewModel? owner, TargetPolicyView policy, bool firewallReadable)
    {
        _record = record;
        _owner = record.ProcessResolved ? owner : null;
        _policy = policy;
        _firewallReadable = firewallReadable;
        RaiseAllPropertiesChanged();
    }

    public bool MatchesSearch(string search)
    {
        if (string.IsNullOrWhiteSpace(search)) return true;
        return SearchText.Contains(search.Trim(), StringComparison.CurrentCultureIgnoreCase);
    }
}
