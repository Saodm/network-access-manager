using System.IO;
using System.Windows.Media;
using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.App.Services;
using NetworkAccessManager.App.ViewModels;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.Models;

public sealed class UiTargetOption
{
    public RuleTargetKind Kind { get; init; }
    public required string Value { get; init; }
    public required string Display { get; init; }
    public string Detail { get; init; } = string.Empty;
    public int PidCount { get; init; }
    public RiskLevel Risk { get; init; }
    public bool CanBlock { get; init; }
    public bool CanScheduleBlock { get; init; }
    public string? IneligibleReason { get; init; }
    public BlockDirections ActiveDirections { get; init; }
    public bool HasManagedActiveRule { get; init; }
    public bool HasInconsistentRule { get; init; }
    public int PendingTaskCount { get; init; }
    public IReadOnlyList<RuleStatusView> Rules { get; init; } = Array.Empty<RuleStatusView>();
    public IReadOnlyList<ScheduledTaskView> Tasks { get; init; } = Array.Empty<ScheduledTaskView>();
    public bool IsNetworkBroad { get; init; }
    public string? NetworkWarning { get; init; }
    public bool RequiresHighRiskAck => Kind == RuleTargetKind.Program && Risk >= RiskLevel.High && CanBlock;

    public string Key => $"{Kind}|{Value.ToLowerInvariant()}";
    public string KindText => Kind switch
    {
        RuleTargetKind.Program => "程序",
        RuleTargetKind.Ethernet => "以太网",
        _ => "网络目标"
    };
    public string DirectionText => ActiveDirections == BlockDirections.None ? "—" : ActiveDirections.ToChinese();
    public Brush RiskBrush => UiBrushes.ForRisk(Risk);
    public string RiskText => Risk switch
    {
        RiskLevel.Critical => "关键",
        RiskLevel.High => "高风险",
        RiskLevel.Caution => "注意",
        _ => "普通"
    };
    public string StatusText => !CanBlock
        ? "不可阻断"
        : HasManagedActiveRule
            ? HasInconsistentRule ? "规则状态异常" : "已有规则"
            : PendingTaskCount > 0 ? "已有任务" : "正常";
    public bool EligibleForMode(ScheduledMode mode)
    {
        if (mode == ScheduledMode.DelayedUnblock)
            return ActiveDirections != BlockDirections.None && !HasInconsistentRule && PendingTaskCount == 0;
        return CanScheduleBlock && !HasManagedActiveRule && PendingTaskCount == 0;
    }
}

public sealed class UiUnblockTarget
{
    public RuleTargetKind Kind { get; init; }
    public required string Value { get; init; }
    public required string Display { get; init; }
    public string Detail { get; init; } = string.Empty;
    public IReadOnlyList<RuleStatusView> Rules { get; init; } = Array.Empty<RuleStatusView>();
    public bool HasInconsistentRule { get; init; }
    public string DirectionsText => Rules.Count == 0
        ? "—"
        : RuleDirectionText(Rules);
    public string StatusText => HasInconsistentRule ? "含状态异常规则" : "生效中";
    public string RuleIds => string.Join(",", Rules.Select(r => r.RuleId));
    public string Key => $"{Kind}|{Value.ToLowerInvariant()}";

    private static string RuleDirectionText(IEnumerable<RuleStatusView> rules)
    {
        var parts = rules.Select(r => r.DirectionText).Distinct().ToList();
        return string.Join("、", parts);
    }
}

public static class UiTargetBuilder
{
    public static IReadOnlyList<UiTargetOption> BuildProgramTargets(
        IReadOnlyList<ProcessRowViewModel> processes,
        IReadOnlyList<ConnectionRowViewModel> connections,
        UiPolicyEvaluator evaluator)
    {
        var groups = new Dictionary<string, Group>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in processes)
        {
            if (string.IsNullOrWhiteSpace(row.ExecutablePath)) continue;
            AddProgram(row.ExecutablePath, row.Pid, row.DisplayName, row.Risk, row.CanBlockProgram,
                row.CanBlockProgram ? null : row.BlockUnavailableReason, row.Connections);
        }
        foreach (var row in connections)
        {
            if (row.OwnerRow is null || string.IsNullOrWhiteSpace(row.ProcessPath)) continue;
            AddProgram(row.ProcessPath!, row.Pid, row.OwnerRow.DisplayName, row.OwnerRow.Risk, row.OwnerRow.CanBlockProgram,
                row.OwnerRow.CanBlockProgram ? null : row.OwnerRow.BlockUnavailableReason, Array.Empty<NetworkConnectionRecord>());
        }

        return groups.Values
            .Select(g =>
            {
                var policy = evaluator.EvaluateProgram(g.Path, g.Connections);
                var pathExists = File.Exists(g.Path);
                var reason = g.IneligibleReason;
                if (!pathExists) reason = "可执行文件当前不存在，无法按此路径安排新的阻断。";
                return new UiTargetOption
                {
                    Kind = RuleTargetKind.Program,
                    Value = g.Path,
                    Display = string.IsNullOrWhiteSpace(g.Name) ? Path.GetFileName(g.Path) : g.Name,
                    Detail = $"{g.Pids.Count} 个 PID：{string.Join(", ", g.Pids.Take(6))}{(g.Pids.Count > 6 ? "…" : string.Empty)}；{g.Path}",
                    PidCount = g.Pids.Count,
                    Risk = g.Risk,
                    CanBlock = g.CanBlock && pathExists,
                    CanScheduleBlock = g.CanBlock && pathExists,
                    IneligibleReason = reason,
                    ActiveDirections = policy.ProgramRuleDirections,
                    HasManagedActiveRule = policy.MatchingRules.Any(r => r.IsActiveRecord && r.Record.TargetKind == RuleTargetKind.Program),
                    HasInconsistentRule = policy.MatchingRules.Any(r => r.IsActiveRecord && (r.IsMismatched || r.IsMissing || r.IsUnknown)),
                    PendingTaskCount = policy.MatchingTasks.Count(t => t.Record.Status == ScheduledTaskStatus.Pending),
                    Rules = policy.MatchingRules.Where(r => r.Record.TargetKind == RuleTargetKind.Program).ToList(),
                    Tasks = policy.MatchingTasks
                };
            })
            .OrderBy(t => t.Display, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        void AddProgram(string path, int pid, string displayName, RiskLevel risk, bool canBlock, string? reason,
            IReadOnlyList<NetworkConnectionRecord> connections)
        {
            var key = ProgramTargetValidator.NormalizeForComparison(path).ToLowerInvariant();
            if (!groups.TryGetValue(key, out var g))
            {
                g = new Group(path, canBlock, reason);
                groups[key] = g;
            }
            g.Pids.Add(pid);
            if (!canBlock) g.CanBlock = false;
            if (reason is not null) g.IneligibleReason ??= reason;
            if (risk > g.Risk) g.Risk = risk;
            if (string.IsNullOrWhiteSpace(g.Name)) g.Name = displayName;
            g.Connections.AddRange(connections);
        }
    }

    public static IReadOnlyList<UiTargetOption> BuildNetworkTargets(
        IReadOnlyList<ConnectionRowViewModel> connections,
        UiPolicyEvaluator evaluator)
    {
        var groups = new Dictionary<string, NetworkGroup>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in connections)
        {
            if (!row.HasRemoteTarget || string.IsNullOrWhiteSpace(row.RemoteAddress)) continue;
            var validation = NetworkTargetValidator.Validate(row.RemoteAddress);
            if (!groups.TryGetValue(row.RemoteAddress, out var g))
            {
                g = new NetworkGroup(row.RemoteAddress, validation);
                groups[row.RemoteAddress] = g;
            }
            g.Pids.Add(row.Pid);
            g.Ports.Add(row.RemotePortText);
        }

        return groups.Values
            .Select(g =>
            {
                var policy = evaluator.EvaluateTarget(RuleTargetKind.NetworkAddress, g.Value);
                var affecting = evaluator.RulesAffectingRemote(g.Value)
                    .Where(r => r.IsVerified)
                    .ToList();
                var hasActiveAffecting = affecting.Count > 0 || policy.HasManagedActiveRule;
                var risk = g.Validation.IsLoopback || g.Validation.IsMulticast ? RiskLevel.Caution :
                    g.Validation.IsBroadScope ? RiskLevel.High : RiskLevel.Normal;
                var warning = g.Validation.Warning;
                return new UiTargetOption
                {
                    Kind = RuleTargetKind.NetworkAddress,
                    Value = g.Value,
                    Display = g.Value,
                    Detail = $"远程端口：{string.Join(", ", g.Ports.Take(6))}；来自 {g.Pids.Count} 个 PID",
                    PidCount = g.Pids.Count,
                    Risk = risk,
                    CanBlock = g.Validation.IsValid,
                    CanScheduleBlock = g.Validation.IsValid && !hasActiveAffecting,
                    IneligibleReason = g.Validation.IsValid ? null : g.Validation.Error,
                    ActiveDirections = policy.VerifiedDirections,
                    HasManagedActiveRule = hasActiveAffecting,
                    HasInconsistentRule = policy.HasInconsistentRule,
                    PendingTaskCount = policy.MatchingTasks.Count(t => t.Record.Status == ScheduledTaskStatus.Pending),
                    Rules = affecting,
                    Tasks = policy.MatchingTasks,
                    IsNetworkBroad = g.Validation.IsBroadScope,
                    NetworkWarning = warning
                };
            })
            .OrderBy(t => t.Display, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static IReadOnlyList<UiUnblockTarget> BuildUnblockTargets(
        IReadOnlyList<ProcessRowViewModel> processes,
        IReadOnlyList<ConnectionRowViewModel> connections)
    {
        var rules = new Dictionary<string, RuleStatusView>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in processes)
            foreach (var rule in row.MatchingRules.Where(r => r.IsActiveRecord))
                rules[rule.RuleId] = rule;
        foreach (var row in connections)
            foreach (var rule in row.MatchingRules.Where(r => r.IsActiveRecord))
                rules[rule.RuleId] = rule;

        return rules.Values
            .GroupBy(r => $"{r.Record.TargetKind}|{r.Record.Target.ToLowerInvariant()}")
            .Select(g =>
            {
                var list = g.OrderBy(r => r.DirectionText).ToList();
                var target = list[0].Record.Target;
                var kind = list[0].Record.TargetKind;
                return new UiUnblockTarget
                {
                    Kind = kind,
                    Value = target,
                    Display = kind == RuleTargetKind.Program ? Path.GetFileName(target) : target,
                    Detail = kind == RuleTargetKind.Program
                        ? target
                        : "网络目标规则会影响所有访问该地址范围的应用程序，不只当前连接。",
                    Rules = list,
                    HasInconsistentRule = list.Any(r => !r.IsVerified)
                };
            })
            .OrderBy(t => t.Display, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private sealed class Group
    {
        public Group(string path, bool canBlock, string? reason)
        {
            Path = path;
            CanBlock = canBlock;
            IneligibleReason = reason;
        }

        public string Path { get; }
        public string? Name { get; set; }
        public bool CanBlock { get; set; }
        public string? IneligibleReason { get; set; }
        public RiskLevel Risk { get; set; } = RiskLevel.Normal;
        public HashSet<int> Pids { get; } = new();
        public List<NetworkConnectionRecord> Connections { get; } = new();
    }

    private sealed class NetworkGroup
    {
        public NetworkGroup(string value, NetworkTargetValidationResult validation)
        {
            Value = value;
            Validation = validation;
        }

        public string Value { get; }
        public NetworkTargetValidationResult Validation { get; }
        public HashSet<int> Pids { get; } = new();
        public HashSet<string> Ports { get; } = new();
    }
}
