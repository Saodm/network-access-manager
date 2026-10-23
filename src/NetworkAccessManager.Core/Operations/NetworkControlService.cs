using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Firewall;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.Core.Operations;

public sealed class ScheduledExecutionResult
{
    public bool Success { get; init; }
    public int ExitCode { get; init; }
    public string Message { get; init; } = string.Empty;
}

/// <summary>
/// The single business layer for rule creation, removal, scheduling and
/// cancellation. Both the UAC helper and the scheduled-task helper enter here,
/// so every mutation follows the same validation, verification and audit path.
/// </summary>
public sealed partial class NetworkControlService
{
    public const int MaxActionsPerRequest = 20;
    private readonly StateRepository _store;
    private readonly IFirewallManager _firewall;
    private readonly IScheduledTaskRegistrar _scheduler;
    private readonly IClock _clock;
    private readonly IAppLog _log;
    private readonly string? _ownExecutablePath;

    private static readonly HashSet<string> HardProtectedSystemBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "smss.exe"
    };

    public NetworkControlService(
        StateRepository store,
        IFirewallManager firewall,
        IScheduledTaskRegistrar scheduler,
        IClock clock,
        IAppLog? log = null,
        string? ownExecutablePath = null)
    {
        _store = store;
        _firewall = firewall;
        _scheduler = scheduler;
        _clock = clock;
        _log = log ?? NullAppLog.Instance;
        _ownExecutablePath = ownExecutablePath;
    }

    public async Task<ElevatedActionResult> RunActionAsync(
        ElevatedAction action,
        string source,
        string? correlationId,
        CancellationToken cancellationToken = default)
    {
        var validationError = ValidateAction(action);
        if (validationError is not null)
        {
            return Failure(action, validationError, source, correlationId);
        }

        if (!_firewall.IsElevated)
        {
            return Failure(action, "此操作需要管理员权限。当前辅助进程没有取得管理员授权，未做任何更改。", source, correlationId);
        }

        try
        {
            using var operationLock = OperationFileLock.Acquire(_store.Paths, _log);
            return action.Kind switch
            {
                ElevatedActionKind.BlockProgram => ExecuteBlock(action, source, correlationId),
                ElevatedActionKind.BlockNetworkAddress => ExecuteBlock(action, source, correlationId),
                ElevatedActionKind.ScheduleDelayedBlock => await ScheduleDelayedBlockAsync(action, source, correlationId, cancellationToken).ConfigureAwait(false),
                ElevatedActionKind.ScheduleDelayedUnblock => await ScheduleDelayedUnblockAsync(action, source, correlationId, cancellationToken).ConfigureAwait(false),
                ElevatedActionKind.ScheduleTimedBlock => await ScheduleTimedBlockAsync(action, source, correlationId, cancellationToken).ConfigureAwait(false),
                ElevatedActionKind.UnblockTarget => await ExecuteUnblockTargetAsync(action, source, correlationId, cancellationToken).ConfigureAwait(false),
                ElevatedActionKind.CancelScheduledTask => await ExecuteCancelScheduledTaskAsync(action, source, correlationId, cancellationToken).ConfigureAwait(false),
                _ => Failure(action, "不支持的操作类型。", source, correlationId)
            };
        }
        catch (OperationBusyException ex)
        {
            _log.Warn("Operations", ex.Message);
            return Failure(action, ex.Message, source, correlationId);
        }
        catch (Exception ex)
        {
            _log.Error("Operations", $"执行操作 {action.Kind} 失败", ex);
            return Failure(action, $"操作失败：{ex.Message}", source, correlationId, ex.ToString());
        }
    }

    private string? ValidateAction(ElevatedAction action)
    {
        if (string.IsNullOrWhiteSpace(action.ActionId))
            return "操作项缺少标识。";
        if (!Enum.IsDefined(action.Kind))
            return "操作类型无效。";
        if ((action.Directions & ~BlockDirections.Both) != 0)
            return "阻断方向包含未知标志。";

        if (action.Kind is not (ElevatedActionKind.CancelScheduledTask or ElevatedActionKind.UnblockTarget))
        {
            if (action.Directions == BlockDirections.None)
                return "必须至少选择一个阻断方向（出站或入站）。";
        }

        if (action.Kind is ElevatedActionKind.ScheduleDelayedBlock or ElevatedActionKind.ScheduleDelayedUnblock or ElevatedActionKind.ScheduleTimedBlock)
        {
            if (action.DelayMinutes is null || action.DelayMinutes < DurationValidator.MinMinutes || action.DelayMinutes > DurationValidator.MaxMinutes)
                return $"延迟时间必须在 {DurationValidator.MinMinutes} 到 {DurationValidator.MaxMinutes} 分钟之间。";
        }

        if (action.Kind == ElevatedActionKind.CancelScheduledTask)
        {
            if (string.IsNullOrWhiteSpace(action.TaskId) || !Guid.TryParseExact(action.TaskId, "N", out _))
                return "要取消的任务 ID 无效。";
            return null;
        }

        if (string.IsNullOrWhiteSpace(action.Target) || action.Target.Length > 32_000)
            return "目标内容为空或过长。";

        if (action.Kind == ElevatedActionKind.BlockProgram && action.TargetKind != RuleTargetKind.Program)
            return "程序阻断操作的目标类型无效。";
        if (action.Kind == ElevatedActionKind.BlockNetworkAddress && action.TargetKind != RuleTargetKind.NetworkAddress)
            return "网络目标阻断操作的目标类型无效。";
        if (action.TargetKind is not (RuleTargetKind.Program or RuleTargetKind.NetworkAddress))
            return "目标类型无效。";
        if (action.Kind is ElevatedActionKind.BlockProgram or ElevatedActionKind.BlockNetworkAddress or
            ElevatedActionKind.ScheduleDelayedBlock or ElevatedActionKind.ScheduleTimedBlock)
        {
            if (action.Directions == BlockDirections.None)
                return "必须至少选择一个阻断方向。";
        }

        return null;
    }

    private ElevatedActionResult ExecuteBlock(ElevatedAction action, string source, string? correlationId)
    {
        ValidatedTarget target;
        try
        {
            target = ValidateTargetForBlock(action.TargetKind, action.Target);
        }
        catch (TargetValidationException ex)
        {
            return Failure(action, ex.Message, source, correlationId);
        }

        var pending = GetPendingTasksForTarget(target);
        if (pending.Count > 0)
        {
            return Failure(action,
                "该对象已有待执行的定时任务。为避免规则与定时操作冲突，请先在“任务与历史”中处理后再重试。",
                source, correlationId,
                string.Join("；", pending.Select(t => $"{t.ModeText} {t.TaskId}")));
        }

        var readiness = CheckFirewallReadyForBlock();
        if (readiness is not null)
            return Failure(action, readiness, source, correlationId);

        StateReadResultGuard(out var state, out var readError);
        if (readError is not null)
            return Failure(action, readError, source, correlationId);

        var active = FindActiveRulesForTarget(state, target).ToList();
        var inspections = active.Count > 0
            ? _firewall.InspectRules(active).Inspections
            : new Dictionary<string, FirewallRuleInspection>(StringComparer.OrdinalIgnoreCase);

        var requestedDirections = action.Directions.ToFirewallDirections().ToList();
        var alreadyCovered = new List<FirewallDirection>();
        var stale = new List<ManagedRuleRecord>();
        foreach (var record in active)
        {
            inspections.TryGetValue(record.RuleId, out var inspection);
            var requestedRecord = requestedDirections.Contains(record.Direction);
            if (inspection is null || inspection.State == RuleInspectionState.Unknown)
            {
                if (requestedRecord)
                    return Failure(action, "无法确认该对象已有的本工具规则状态，未创建新规则。请稍后刷新或在“任务与历史”中检查。", source, correlationId);
                continue;
            }
            if (inspection.State == RuleInspectionState.Mismatched)
            {
                if (requestedRecord)
                    return Failure(action,
                        $"该对象已有的本工具规则已被外部修改：{inspection.Detail} 为避免状态冲突，请先在规则管理中处理。",
                        source, correlationId);
                continue;
            }
            if (inspection.State == RuleInspectionState.Missing)
            {
                if (requestedRecord) stale.Add(record);
                continue;
            }
            if (requestedRecord)
                alreadyCovered.Add(record.Direction);
        }

        var safeAlreadyCovered = alreadyCovered.Distinct().ToList();
        var missingDirections = requestedDirections.Where(d => !safeAlreadyCovered.Contains(d)).ToList();
        if (missingDirections.Count == 0)
        {
            var message = "所选方向的阻断规则已经存在且属性一致，未重复创建。";
            SafeAppendEvent(NewEvent(
                "立即禁止", target, OperationOutcome.Info, message, null,
                source, correlationId, ruleIds: active.Select(r => r.RuleId).Where(id => inspections.TryGetValue(id, out var i) && i.State == RuleInspectionState.Verified).ToList()));
            return new ElevatedActionResult
            {
                ActionId = action.ActionId,
                Success = true,
                Outcome = OperationOutcome.Info,
                Message = message,
                RuleIds = active.Where(r => inspections.TryGetValue(r.RuleId, out var i) && i.State == RuleInspectionState.Verified).Select(r => r.RuleId).ToList()
            };
        }

        var created = new List<RuleBuild>();
        try
        {
            var plans = BuildRulePlans(target, missingDirections, _clock.UtcNow, WindowsPrivilege.CurrentUserName());
            var definitions = plans.Select(p => p.Definition).ToList();
            var inspectionsAfter = _firewall.CreateRules(definitions);
            if (inspectionsAfter.Any(i => i.State != RuleInspectionState.Verified))
                throw new FirewallOperationException("防火墙规则创建后的验证结果不是全部一致。");

            created.AddRange(plans);
            var now = _clock.UtcNow;
            var ruleIds = plans.Select(p => p.Record.RuleId).ToList();
            var directionText = DirectionText.DescribeRules(missingDirections);
            var message = action.TargetKind == RuleTargetKind.Program
                ? $"已创建并验证 {plans.Count} 条程序阻断规则（{directionText}）。规则按可执行文件路径生效，可能影响同一程序启动的全部实例。"
                : $"已创建并验证 {plans.Count} 条网络目标阻断规则（{directionText}）。规则会影响访问该地址范围的全部应用。";
            if (safeAlreadyCovered.Count > 0)
                message += $" 已存在且复用的方向：{DirectionText.DescribeRules(safeAlreadyCovered)}。";

            try
            {
                _store.Mutate(s =>
                {
                    foreach (var record in stale)
                    {
                        var stored = s.Rules.FirstOrDefault(r => r.RuleId == record.RuleId);
                        if (stored is not null)
                        {
                            stored.Status = ManagedRuleStatus.RemovedExternally;
                            stored.VerifiedUtc = now;
                            stored.Note = "创建新规则时发现原规则已不在 Windows 防火墙中。";
                        }
                    }
                    foreach (var build in plans)
                        s.Rules.Add(build.Record);
                    s.Events.Add(NewEvent(
                        "立即禁止", target, OperationOutcome.Success, message,
                        string.Join(Environment.NewLine, plans.Select(p => $"{p.Record.FirewallRuleName} ({p.Record.Direction.ToShortChinese()})")),
                        source, correlationId, ruleIds: ruleIds));
                });
            }
            catch (Exception stateError)
            {
                _log.Error("Operations", "阻断规则已创建但状态保存失败，开始回滚规则", stateError);
                var cleanupFailures = CleanupCreatedRules(created);
                var detail = cleanupFailures.Count == 0
                    ? "状态数据保存失败，已回滚新创建的防火墙规则。"
                    : $"状态数据保存失败，且以下新规则回滚失败，请人工检查：{string.Join("；", cleanupFailures)}";
                TryLogFailureEvent("立即禁止", target, source, correlationId, detail);
                return Failure(action, stateError.Message, source, correlationId, detail, OperationOutcome.Failure);
            }

            return new ElevatedActionResult
            {
                ActionId = action.ActionId,
                Success = true,
                Outcome = OperationOutcome.Success,
                Message = message,
                RuleIds = ruleIds
            };
        }
        catch (Exception ex)
        {
            _log.Error("Operations", "创建阻断规则失败", ex);
            if (created.Count > 0)
            {
                var cleanupFailures = CleanupCreatedRules(created);
                if (cleanupFailures.Count > 0)
                    TryLogFailureEvent("立即禁止", target, source, correlationId, "规则回滚失败：" + string.Join("；", cleanupFailures));
            }
            TryLogFailureEvent("立即禁止", target, source, correlationId, ex.Message);
            return Failure(action, ex.Message, source, correlationId, ex.ToString());
        }
    }

    private void StateReadResultGuard(out AppState state, out string? error)
    {
        try
        {
            var result = _store.ReadState();
            state = result.State;
            error = null;
            if (result.UsedBackup && result.Warning is not null)
                _log.Warn("State", result.Warning);
        }
        catch (Exception ex)
        {
            state = new AppState();
            error = $"无法读取本工具状态数据：{ex.Message}";
        }
    }

    private string? CheckFirewallReadyForBlock()
    {
        FirewallAvailability availability;
        try
        {
            availability = _firewall.GetAvailability();
        }
        catch (Exception ex)
        {
            return $"无法读取 Windows 防火墙状态：{ex.Message}";
        }

        if (!availability.IsAvailable)
            return $"Windows 防火墙不可用，无法创建可靠规则：{availability.Error ?? availability.StatusText}";
        if (!availability.CanReadRules)
            return $"无法读取现有 Windows 防火墙规则，为避免重复或误删，已拒绝创建：{availability.Error ?? availability.StatusText}";
        if (!availability.IsCurrentProfileProtected)
            return availability.Error ?? "当前网络配置文件的 Windows 防火墙未启用，无法保证规则生效。本工具不会修改 Windows 防火墙的全局启用状态。";
        return null;
    }

    private List<ManagedRuleRecord> FindActiveRulesForTarget(AppState state, ValidatedTarget target)
    {
        return state.Rules
            .Where(r => r.Status == ManagedRuleStatus.Active)
            .Where(r => TargetMatches(r.TargetKind, r.Target, target))
            .ToList();
    }

    private List<ScheduledTaskRecord> GetPendingTasksForTarget(ValidatedTarget target)
    {
        try
        {
            var state = _store.ReadState().State;
            return state.Tasks
                .Where(t => t.Status is ScheduledTaskStatus.Pending or ScheduledTaskStatus.Running)
                .Where(t => t.TargetKind == target.Kind && TargetMatches(t.TargetKind, t.Target, target))
                .ToList();
        }
        catch
        {
            return new List<ScheduledTaskRecord>();
        }
    }

    private ValidatedTarget ValidateTargetForBlock(RuleTargetKind kind, string? target)
    {
        if (kind == RuleTargetKind.Program)
        {
            var validation = ProgramTargetValidator.Validate(target, _ownExecutablePath);
            if (!validation.IsValid)
                throw new TargetValidationException(validation.Error ?? "程序路径无效。");
            var path = validation.NormalizedPath!;
            EnsureNotHardProtected(path);
            return new ValidatedTarget(kind, path, path);
        }
        else
        {
            var validation = NetworkTargetValidator.Validate(target);
            if (!validation.IsValid)
                throw new TargetValidationException(validation.Error ?? "网络目标无效。");
            return new ValidatedTarget(kind, validation.NormalizedTarget!, validation.NormalizedTarget!);
        }
    }

    private ValidatedTarget ValidateExistingTarget(RuleTargetKind kind, string? target)
    {
        if (kind == RuleTargetKind.Program)
        {
            if (string.IsNullOrWhiteSpace(target) || !Path.IsPathFullyQualified(target))
                throw new TargetValidationException("程序目标必须是完整路径。");
            var path = ProgramTargetValidator.NormalizeForComparison(target);
            return new ValidatedTarget(kind, path, path);
        }

        var validation = NetworkTargetValidator.Validate(target);
        if (!validation.IsValid)
            throw new TargetValidationException(validation.Error ?? "网络目标无效。");
        return new ValidatedTarget(kind, validation.NormalizedTarget!, validation.NormalizedTarget!);
    }

    private void EnsureNotHardProtected(string programPath)
    {
        if (_ownExecutablePath is not null && ProgramTargetValidator.PathsEqual(programPath, _ownExecutablePath))
            throw new TargetValidationException("不能阻断本工具自身，否则将无法执行恢复、取消和审计操作。");

        var systemDirs = new[]
        {
            Environment.SystemDirectory,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")
        };
        foreach (var directory in systemDirs)
        {
            foreach (var binary in HardProtectedSystemBinaries)
            {
                var candidate = Path.Combine(directory, binary);
                if (ProgramTargetValidator.PathsEqual(programPath, candidate))
                    throw new TargetValidationException(
                        $"{binary} 是关键 Windows 网络/系统组件。本工具禁止按程序路径整体阻断它，以免破坏登录、系统启动或网络基础功能。");
            }
        }
    }

    private List<RuleBuild> BuildRulePlans(
        ValidatedTarget target,
        IEnumerable<FirewallDirection> directions,
        DateTimeOffset createdUtc,
        string createdBy)
    {
        var operationGroup = Guid.NewGuid().ToString("N");
        var plans = new List<RuleBuild>();
        foreach (var direction in directions.Distinct())
        {
            var ruleId = Guid.NewGuid().ToString("N");
            var metadata = FirewallRuleMetadata.Create(ruleId, direction, target.Kind, target.Value, WindowsPrivilege.CurrentUserSid(), createdUtc);
            var description = metadata.ToDescription();
            var name = FirewallRuleMetadata.BuildRuleName(ruleId, direction);
            plans.Add(new RuleBuild(
                new RuleDefinition
                {
                    RuleId = ruleId,
                    FirewallRuleName = name,
                    Description = description,
                    TargetKind = target.Kind,
                    Target = target.Value,
                    Direction = direction
                },
                new ManagedRuleRecord
                {
                    RuleId = ruleId,
                    TargetKind = target.Kind,
                    Target = target.Value,
                    DisplayTarget = target.Display,
                    Direction = direction,
                    FirewallRuleName = name,
                    Description = description,
                    Status = ManagedRuleStatus.Active,
                    CreatedUtc = createdUtc,
                    CreatedBy = createdBy,
                    OperationGroupId = operationGroup,
                    VerifiedUtc = createdUtc
                }));
        }
        return plans;
    }

    private List<RuleBuildFromRecord> BuildPlansFromRecords(IEnumerable<ManagedRuleRecord> records)
    {
        return records.Select(record =>
        {
            var metadata = FirewallRuleMetadata.Create(
                record.RuleId,
                record.Direction,
                record.TargetKind,
                record.Target,
                WindowsPrivilege.CurrentUserSid(),
                record.CreatedUtc);
            return new RuleBuildFromRecord(record, metadata.ToDescription());
        }).ToList();
    }

    private List<string> CleanupCreatedRules(IEnumerable<RuleBuild> builds)
    {
        var failures = new List<string>();
        foreach (var build in builds)
        {
            try
            {
                _firewall.RemoveRule(build.Definition.FirewallRuleName, build.Definition.RuleId);
            }
            catch (Exception ex)
            {
                failures.Add($"{build.Record.Target} {build.Record.Direction.ToShortChinese()}：{ex.Message}");
                _log.Error("Operations", $"回滚防火墙规则失败：{build.Definition.FirewallRuleName}", ex);
            }
        }
        return failures;
    }

    private ElevatedActionResult Failure(
        ElevatedAction action,
        string message,
        string source,
        string? correlationId,
        string? detail = null,
        OperationOutcome outcome = OperationOutcome.Failure)
    {
        _log.Warn("Operations", $"{action.Kind} 失败：{message}");
        var target = string.IsNullOrWhiteSpace(action.Target)
            ? null
            : new ValidatedTarget(action.TargetKind, action.Target, action.Target);
        TryLogFailureEvent($"操作（{action.Kind}）", target, source, correlationId, message + (detail is null ? string.Empty : Environment.NewLine + detail), action.TaskId);
        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = false,
            Outcome = outcome,
            Message = message,
            Detail = detail,
            TaskId = action.TaskId
        };
    }

    private static string TryDescribeActionTarget(ElevatedAction action) =>
        string.IsNullOrWhiteSpace(action.Target) ? "(无目标)" : action.Target!;

    private void TryLogFailureEvent(string operation, ValidatedTarget? target, string source, string? correlationId, string detail, string? taskId = null)
    {
        try
        {
            _store.Mutate(state =>
            {
                var history = new OperationHistoryEvent
                {
                    TimestampUtc = _clock.UtcNow,
                    Operation = operation,
                    TargetKind = target?.Kind,
                    Target = target?.Value,
                    TargetPath = target?.Kind == RuleTargetKind.Program ? target.Value : null,
                    TaskId = taskId,
                    Outcome = OperationOutcome.Failure,
                    Message = "操作失败",
                    Detail = detail,
                    Source = source,
                    CorrelationId = correlationId
                };
                state.Events.Add(history);
            });
        }
        catch (Exception ex)
        {
            _log.Error("Audit", "写入失败历史记录失败", ex);
        }
    }

    private void SafeAppendEvent(OperationHistoryEvent historyEvent)
    {
        try
        {
            _store.AppendEvent(historyEvent);
        }
        catch (Exception ex)
        {
            _log.Error("Audit", "写入历史记录失败", ex);
        }
    }

    private OperationHistoryEvent NewEvent(
        string operation,
        ValidatedTarget target,
        OperationOutcome outcome,
        string message,
        string? detail,
        string source,
        string? correlationId,
        IReadOnlyList<string>? ruleIds = null,
        string? ruleId = null,
        string? taskId = null,
        DateTimeOffset? plannedUtc = null,
        DateTimeOffset? actualUtc = null,
        string? targetPathOverride = null)
    {
        var ids = ruleIds is { Count: > 0 } ? string.Join(",", ruleIds) : ruleId;
        return new OperationHistoryEvent
        {
            TimestampUtc = _clock.UtcNow,
            Operation = operation,
            TargetKind = target.Kind,
            Target = target.Value,
            TargetPath = targetPathOverride ?? (target.Kind == RuleTargetKind.Program ? target.Value : null),
            RuleId = ids,
            TaskId = taskId,
            PlannedUtc = plannedUtc,
            ActualUtc = actualUtc,
            Outcome = outcome,
            Message = message,
            Detail = detail,
            Source = source,
            CorrelationId = correlationId
        };
    }

    private static bool TargetMatches(RuleTargetKind kind, string stored, ValidatedTarget target) =>
        kind == target.Kind &&
        (kind == RuleTargetKind.Program
            ? ProgramTargetValidator.PathsEqual(stored, target.Value)
            : string.Equals(stored.Trim(), target.Value.Trim(), StringComparison.OrdinalIgnoreCase));

    private sealed record RuleBuild(RuleDefinition Definition, ManagedRuleRecord Record);
    private sealed record RuleBuildFromRecord(ManagedRuleRecord Record, string Description);
    private sealed record ValidatedTarget(RuleTargetKind Kind, string Value, string Display);

    private sealed class TargetValidationException : Exception
    {
        public TargetValidationException(string message) : base(message) { }
    }
}
