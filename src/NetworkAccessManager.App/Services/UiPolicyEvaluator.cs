using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.Services;

/// <summary>
/// Builds the displayed policy state exclusively from persisted rule records,
/// live Windows Firewall inspections, and persisted task state. It never infers
/// "blocked" from a previous button press. Missing/unreadable rules remain
/// visibly distinct from verified blocks.
/// </summary>
public sealed class UiPolicyEvaluator
{
    private readonly AppState _state;
    private readonly FirewallInspectionBatch _batch;
    private readonly DateTimeOffset _now;

    public UiPolicyEvaluator(AppState state, FirewallInspectionBatch batch, DateTimeOffset now)
    {
        _state = state;
        _batch = batch;
        _now = now;
        Rules = state.Rules
            .OrderByDescending(r => r.CreatedUtc)
            .Select(r => new RuleStatusView
            {
                Record = r,
                Inspection = batch.Inspections.TryGetValue(r.RuleId, out var inspection) ? inspection : null,
                Availability = batch.Availability,
                Now = now
            })
            .ToList();
        Tasks = state.Tasks
            .OrderByDescending(t => t.CreatedUtc)
            .Select(t => new ScheduledTaskView { Record = t, Now = now })
            .ToList();
    }

    public IReadOnlyList<RuleStatusView> Rules { get; }
    public IReadOnlyList<ScheduledTaskView> Tasks { get; }
    public FirewallAvailability Firewall => _batch.Availability;
    public DateTimeOffset CapturedUtc { get; } = DateTimeOffset.UtcNow;

    public TargetPolicyView EvaluateProgram(string? programPath, IReadOnlyList<NetworkConnectionRecord>? connections = null)
    {
        if (string.IsNullOrWhiteSpace(programPath))
        {
            return BuildPolicy(Array.Empty<RuleStatusView>(), Array.Empty<ScheduledTaskView>(), PolicyScope.Process,
                targetRuleImpactCount: CountTargetRuleImpacts(connections));
        }

        var rules = Rules
            .Where(r => r.IsActiveRecord && r.Record.TargetKind == RuleTargetKind.Program)
            .Where(r => ProgramTargetValidator.PathsEqual(r.Record.Target, programPath))
            .ToList();
        var tasks = Tasks
            .Where(t => t.Record.TargetKind == RuleTargetKind.Program)
            .Where(t => ProgramTargetValidator.PathsEqual(t.Record.Target, programPath))
            .ToList();
        return BuildPolicy(rules, tasks, PolicyScope.Process,
            targetRuleImpactCount: CountTargetRuleImpacts(connections));
    }

    public TargetPolicyView EvaluateConnection(NetworkConnectionRecord connection)
    {
        var programRules = string.IsNullOrWhiteSpace(connection.ProcessPath)
            ? new List<RuleStatusView>()
            : Rules
                .Where(r => r.IsActiveRecord && r.Record.TargetKind == RuleTargetKind.Program)
                .Where(r => ProgramTargetValidator.PathsEqual(r.Record.Target, connection.ProcessPath))
                .ToList();
        var networkRules = string.IsNullOrWhiteSpace(connection.RemoteAddress)
            ? new List<RuleStatusView>()
            : FindNetworkRulesForRemote(connection.RemoteAddress);
        var programTasks = string.IsNullOrWhiteSpace(connection.ProcessPath)
            ? new List<ScheduledTaskView>()
            : Tasks
                .Where(t => t.Record.TargetKind == RuleTargetKind.Program)
                .Where(t => ProgramTargetValidator.PathsEqual(t.Record.Target, connection.ProcessPath))
                .ToList();
        var networkTasks = string.IsNullOrWhiteSpace(connection.RemoteAddress)
            ? new List<ScheduledTaskView>()
            : Tasks
                .Where(t => t.Record.TargetKind == RuleTargetKind.NetworkAddress)
                .Where(t => string.Equals(t.Record.Target, connection.RemoteAddress, StringComparison.OrdinalIgnoreCase))
                .ToList();
        var allTasks = programTasks.Concat(networkTasks)
            .GroupBy(t => t.TaskId)
            .Select(g => g.First())
            .ToList();
        return BuildPolicy(programRules, allTasks, PolicyScope.Connection, secondaryRules: networkRules);
    }

    public TargetPolicyView EvaluateTarget(RuleTargetKind kind, string target)
    {
        var rules = Rules
            .Where(r => r.IsActiveRecord && r.Record.TargetKind == kind)
            .Where(r => kind == RuleTargetKind.Program
                ? ProgramTargetValidator.PathsEqual(r.Record.Target, target)
                : string.Equals(r.Record.Target.Trim(), target.Trim(), StringComparison.OrdinalIgnoreCase))
            .ToList();
        var tasks = Tasks
            .Where(t => t.Record.TargetKind == kind)
            .Where(t => kind == RuleTargetKind.Program
                ? ProgramTargetValidator.PathsEqual(t.Record.Target, target)
                : string.Equals(t.Record.Target.Trim(), target.Trim(), StringComparison.OrdinalIgnoreCase))
            .ToList();
        return BuildPolicy(rules, tasks, PolicyScope.Target);
    }

    public IReadOnlyList<RuleStatusView> RulesForProgram(string? path) =>
        string.IsNullOrWhiteSpace(path)
            ? Array.Empty<RuleStatusView>()
            : Rules.Where(r => r.IsActiveRecord && r.Record.TargetKind == RuleTargetKind.Program)
                .Where(r => ProgramTargetValidator.PathsEqual(r.Record.Target, path))
                .ToList();

    public IReadOnlyList<RuleStatusView> RulesForNetworkTarget(string? target) =>
        string.IsNullOrWhiteSpace(target)
            ? Array.Empty<RuleStatusView>()
            : Rules.Where(r => r.IsActiveRecord && r.Record.TargetKind == RuleTargetKind.NetworkAddress)
                .Where(r => string.Equals(r.Record.Target.Trim(), target.Trim(), StringComparison.OrdinalIgnoreCase))
                .ToList();

    public IReadOnlyList<RuleStatusView> RulesAffectingRemote(string? remoteAddress) =>
        string.IsNullOrWhiteSpace(remoteAddress) ? Array.Empty<RuleStatusView>() : FindNetworkRulesForRemote(remoteAddress);

    public int CountTargetRuleImpacts(IReadOnlyList<NetworkConnectionRecord>? connections)
    {
        if (connections is null || connections.Count == 0) return 0;
        var networkRules = Rules.Where(r => r.IsActiveRecord && r.IsVerified && r.Record.TargetKind == RuleTargetKind.NetworkAddress).ToList();
        if (networkRules.Count == 0) return 0;
        var count = 0;
        foreach (var connection in connections)
        {
            if (string.IsNullOrWhiteSpace(connection.RemoteAddress)) continue;
            if (networkRules.Any(r => NetworkAddressMatcher.Matches(r.Record.Target, connection.RemoteAddress)))
                count++;
        }
        return count;
    }

    private List<RuleStatusView> FindNetworkRulesForRemote(string remoteAddress) =>
        Rules
            .Where(r => r.IsActiveRecord && r.Record.TargetKind == RuleTargetKind.NetworkAddress)
            .Where(r => NetworkAddressMatcher.Matches(r.Record.Target, remoteAddress))
            .ToList();

    private TargetPolicyView BuildPolicy(
        IReadOnlyList<RuleStatusView> primaryRules,
        IReadOnlyList<ScheduledTaskView> tasks,
        PolicyScope scope,
        int targetRuleImpactCount = 0,
        IReadOnlyList<RuleStatusView>? secondaryRules = null)
    {
        secondaryRules ??= Array.Empty<RuleStatusView>();
        var allRules = primaryRules.Concat(secondaryRules).GroupBy(r => r.RuleId).Select(g => g.First()).ToList();
        var primaryDirections = ToDirections(primaryRules.Where(r => r.IsVerified).Select(r => r.Record.Direction));
        var secondaryDirections = ToDirections(secondaryRules.Where(r => r.IsVerified).Select(r => r.Record.Direction));
        var verifiedDirections = ToDirections(allRules.Where(r => r.IsVerified).Select(r => r.Record.Direction));
        var hasManagedActive = allRules.Any(r => r.IsActiveRecord);
        var mismatched = allRules.Count(r => r.IsMismatched);
        var missing = allRules.Count(r => r.IsMissing);
        var unknown = allRules.Count(r => r.IsUnknown);
        var hasInconsistent = mismatched + missing > 0;
        var firewallUnreadable = !_batch.Availability.CanReadRules;
        var pendingTasks = tasks.Where(t => t.Record.Status is ScheduledTaskStatus.Pending or ScheduledTaskStatus.Running)
            .OrderBy(t => t.Record.Status == ScheduledTaskStatus.Running ? 0 : 1)
            .ThenBy(t => t.Record.PlannedUtc)
            .ToList();
        var recentFailed = tasks.Where(t => t.IsFailure && t.Record.CompletedUtc is { } completed && _now - completed < TimeSpan.FromHours(24))
            .OrderByDescending(t => t.Record.CompletedUtc)
            .ToList();
        var autoUnblock = pendingTasks.FirstOrDefault(t => t.IsAutoUnblock);
        var nextAuto = autoUnblock?.Record.PlannedUtc;
        var mostUrgent = pendingTasks.FirstOrDefault();

        var textParts = new List<string>();
        switch (scope)
        {
            case PolicyScope.Process:
                if (primaryDirections != BlockDirections.None)
                    textParts.Add($"已禁止（{primaryDirections.ToChinese().Replace("仅", string.Empty)}）");
                else if (hasInconsistent && !firewallUnreadable)
                    textParts.Add("规则状态不一致");
                else if (hasManagedActive && (unknown > 0 || firewallUnreadable))
                    textParts.Add("已登记阻断（待复核）");
                else
                    textParts.Add("未禁止");
                if (targetRuleImpactCount > 0)
                    textParts.Add($"{targetRuleImpactCount} 个连接受目标规则影响");
                break;
            case PolicyScope.Connection:
                if (primaryDirections != BlockDirections.None)
                    textParts.Add($"程序已禁止（{primaryDirections.ToChinese().Replace("仅", string.Empty)}）");
                if (secondaryDirections != BlockDirections.None)
                    textParts.Add($"目标已禁止（{secondaryDirections.ToChinese().Replace("仅", string.Empty)}）");
                if (textParts.Count == 0)
                    textParts.Add(hasInconsistent && !firewallUnreadable ? "规则异常" :
                        hasManagedActive && (unknown > 0 || firewallUnreadable) ? "已登记禁止（待复核）" : "未禁止");
                break;
            default:
                if (verifiedDirections != BlockDirections.None)
                    textParts.Add($"已禁止（{verifiedDirections.ToChinese().Replace("仅", string.Empty)}）");
                else if (hasInconsistent && !firewallUnreadable)
                    textParts.Add("规则状态不一致");
                else if (hasManagedActive && (unknown > 0 || firewallUnreadable))
                    textParts.Add("已登记禁止（待复核）");
                else
                    textParts.Add("未禁止");
                break;
        }

        var pendingDescriptor = BuildPendingDescriptor(mostUrgent, verifiedDirections, scope);
        if (!string.IsNullOrWhiteSpace(pendingDescriptor))
            textParts.Add(pendingDescriptor);
        var kind = DetermineKind(verifiedDirections, scope, primaryDirections, secondaryDirections, hasInconsistent,
            hasManagedActive, unknown, firewallUnreadable, pendingTasks, mostUrgent, recentFailed);
        if (!firewallUnreadable && verifiedDirections == BlockDirections.None && pendingTasks.Count == 0 && recentFailed.Count == 0 && textParts.Count == 1 && textParts[0] == "未禁止")
            kind = PolicyStateKind.Normal;

        var detailLines = new List<string>();
        if (allRules.Count == 0 && tasks.Count == 0)
            detailLines.Add("没有由本工具登记且适用于此对象的规则或定时任务。");
        foreach (var rule in allRules)
            detailLines.Add($"{rule.DirectionText}规则：{rule.StatusText}。{rule.StatusDetail}");
        foreach (var task in pendingTasks)
            detailLines.Add($"{task.ModeText}任务：{task.StatusText}；{task.RemainingText}；计划 {task.PlannedText}。");
        foreach (var failed in recentFailed)
            detailLines.Add($"{failed.ModeText}任务失败：{failed.FailureText}");
        if (targetRuleImpactCount > 0)
            detailLines.Add($"该程序当前有 {targetRuleImpactCount} 个连接命中已生效的网络目标规则。");
        if (firewallUnreadable && hasManagedActive)
            detailLines.Add("“已登记禁止（待复核）”表示该规则由本工具在之前的提权操作中创建并核验过，但当前普通权限会话无法重新读取防火墙；外部修改需要在管理员会话或规则页刷新后确认。");

        var hasFailure = hasInconsistent || recentFailed.Count > 0 || pendingTasks.Any(t => t.EffectiveState == EffectiveTaskState.StaleRunning) ||
                         pendingTasks.Any(t => t.EffectiveState == EffectiveTaskState.Overdue && !t.IsAutoUnblock);
        var hasPending = pendingTasks.Count > 0;
        var hasOverdue = pendingTasks.Any(t => t.IsOverdue);

        return new TargetPolicyView
        {
            Text = string.Join(" · ", textParts),
            Detail = string.Join(Environment.NewLine, detailLines.Distinct()),
            Kind = kind,
            VerifiedDirections = verifiedDirections,
            ProgramRuleDirections = primaryDirections,
            NetworkRuleDirections = secondaryDirections,
            HasManagedActiveRule = hasManagedActive,
            HasInconsistentRule = hasInconsistent,
            HasUnknownRule = unknown > 0 || (firewallUnreadable && hasManagedActive),
            HasPendingTask = hasPending,
            HasFailure = hasFailure,
            HasOverdueTask = hasOverdue,
            PendingTaskCount = pendingTasks.Count,
            FailedTaskCount = recentFailed.Count,
            ActiveRuleCount = allRules.Count(r => r.IsVerified),
            TargetRuleImpactCount = targetRuleImpactCount,
            NextAutoUnblockUtc = nextAuto,
            NextPlannedTaskUtc = mostUrgent?.Record.PlannedUtc,
            NextTaskSummary = mostUrgent is null ? null : $"{mostUrgent.ModeText}：{mostUrgent.StatusText}，{mostUrgent.RemainingText}",
            MatchingRules = allRules,
            MatchingTasks = tasks
        };
    }

    private PolicyStateKind DetermineKind(
        BlockDirections verifiedDirections,
        PolicyScope scope,
        BlockDirections primaryDirections,
        BlockDirections secondaryDirections,
        bool hasInconsistent,
        bool hasManagedActive,
        int unknown,
        bool firewallUnreadable,
        IReadOnlyList<ScheduledTaskView> pendingTasks,
        ScheduledTaskView? mostUrgent,
        IReadOnlyList<ScheduledTaskView> recentFailed)
    {
        if (pendingTasks.Any(t => t.EffectiveState is EffectiveTaskState.Running))
            return PolicyStateKind.Running;
        if (hasInconsistent)
            return PolicyStateKind.Inconsistent;
        if (hasManagedActive && (unknown > 0 || firewallUnreadable))
            return PolicyStateKind.Unknown;
        if (pendingTasks.Any(t => t.EffectiveState is EffectiveTaskState.Overdue))
            return PolicyStateKind.Waiting;
        if (verifiedDirections != BlockDirections.None)
        {
            var activeDirections = scope == PolicyScope.Process ? primaryDirections :
                scope == PolicyScope.Connection ? primaryDirections | secondaryDirections : verifiedDirections;
            if (activeDirections != BlockDirections.None && pendingTasks.Any(t => t.IsAutoUnblock))
                return PolicyStateKind.Limited;
            return PolicyStateKind.Blocked;
        }
        if (pendingTasks.Count > 0)
            return PolicyStateKind.Waiting;
        if (recentFailed.Count > 0)
            return PolicyStateKind.Failure;
        return PolicyStateKind.Normal;
    }

    private string? BuildPendingDescriptor(ScheduledTaskView? task, BlockDirections activeDirections, PolicyScope scope)
    {
        if (task is null) return null;
        var remaining = task.RemainingText;
        if (task.Record.Status == ScheduledTaskStatus.Running)
            return "任务执行中";
        if (task.Record.Status != ScheduledTaskStatus.Pending) return null;
        if (task.EffectiveState is EffectiveTaskState.Overdue)
            return task.IsAutoUnblock ? "自动解除任务已超时，等待系统补执行" : "定时任务已超时，等待系统补执行";
        if (task.EffectiveState is EffectiveTaskState.Due)
            return task.IsAutoUnblock ? "即将自动解除" : "即将执行";
        if (task.Record.Mode == ScheduledMode.TimedBlock)
            return activeDirections != BlockDirections.None
                ? $"限时禁止中，{remaining}后自动解除"
                : $"自动解除任务等待中（{remaining}）";
        if (task.Record.Mode == ScheduledMode.DelayedUnblock)
            return activeDirections != BlockDirections.None
                ? $"等待自动解除（{remaining}）"
                : $"解除任务等待中（{remaining}）";
        if (task.Record.Mode == ScheduledMode.DelayedBlock)
            return $"等待延迟禁止（{remaining}）";
        return $"等待任务执行（{remaining}）";
    }

    private static BlockDirections ToDirections(IEnumerable<FirewallDirection> directions)
    {
        var result = BlockDirections.None;
        foreach (var direction in directions)
        {
            result |= direction == FirewallDirection.Outbound ? BlockDirections.Outbound : BlockDirections.Inbound;
        }
        return result;
    }

    private enum PolicyScope
    {
        Process,
        Connection,
        Target
    }
}
