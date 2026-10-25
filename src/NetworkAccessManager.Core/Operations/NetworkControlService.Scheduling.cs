using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.Core.Operations;

public sealed partial class NetworkControlService
{
    private async Task<ElevatedActionResult> ScheduleDelayedBlockAsync(
        ElevatedAction action,
        string source,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        ValidatedTarget target;
        try { target = ValidateTargetForBlock(action.TargetKind, action.Target); }
        catch (TargetValidationException ex) { return Failure(action, ex.Message, source, correlationId); }

        var pending = GetPendingTasksForTarget(target);
        if (pending.Count > 0)
            return Failure(action, "该对象已有待执行或正在执行的定时任务。为避免多个定时操作互相覆盖，请先取消现有任务。", source, correlationId);

        StateReadResultGuard(out var state, out var stateError);
        if (stateError is not null) return Failure(action, stateError, source, correlationId);
        if (FindActiveRulesForTarget(state, target).Count > 0)
            return Failure(action, "该对象已有本工具创建的阻断规则。延迟禁止没有意义；如希望限时阻断，请先解除当前规则后使用“限时禁止”，或使用“延迟解除”。", source, correlationId);

        var readiness = CheckFirewallReadyForBlock();
        if (readiness is not null)
            return Failure(action, "当前 Windows 防火墙状态无法保证未来规则生效：" + readiness, source, correlationId);

        var delay = action.DelayMinutes!.Value;
        var now = _clock.UtcNow;
        var plannedUtc = now.AddMinutes(delay);
        var taskId = Guid.NewGuid().ToString("N");
        var taskName = Scheduling.TaskNamePolicy.ForTask(taskId);
        var builds = BuildRulePlans(target, action.Directions.ToFirewallDirections(), now, WindowsPrivilege.CurrentUserName());
        var record = BuildScheduledTask(taskId, taskName, ScheduledMode.DelayedBlock, ScheduledExecutionAction.Block,
            target, action.Directions, builds.Select(b => b.Record).ToList(), now, plannedUtc, correlationId);

        try
        {
            await _scheduler.RegisterAsync(
                taskName,
                $"--execute-task={taskId}",
                plannedUtc,
                BuildScheduleDescription("延迟禁止", target),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Error("Schedule", "注册延迟禁止计划任务失败", ex);
            TryLogFailureEvent("延迟禁止", target, source, correlationId, ex.Message, taskId);
            return Failure(action, $"无法注册 Windows 计划任务：{ex.Message}", source, correlationId, ex.ToString());
        }

        try
        {
            _store.Mutate(s =>
            {
                s.Tasks.Add(record);
                s.Events.Add(NewEvent(
                    "延迟禁止", target, OperationOutcome.Success,
                    $"已创建延迟禁止任务，计划于 {TimeDisplay.LocalDateTime(plannedUtc)} 执行。",
                    $"规则将在执行时创建：{string.Join("、", builds.Select(b => b.Record.Direction.ToShortChinese()))}",
                    source, correlationId, taskId: taskId, plannedUtc: plannedUtc));
            });
        }
        catch (Exception ex)
        {
            await TryDeleteTaskAsync(taskName).ConfigureAwait(false);
            _log.Error("Schedule", "延迟禁止任务状态保存失败", ex);
            return Failure(action, $"状态数据保存失败，计划任务已回滚：{ex.Message}", source, correlationId, ex.ToString());
        }

        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = true,
            Outcome = OperationOutcome.Success,
            Message = $"已创建延迟禁止任务。将在 {delay} 分钟后（{TimeDisplay.LocalDateTime(plannedUtc)}）禁止该对象的{DirectionText.ToChinese(action.Directions)}访问。若电脑休眠或关机，系统会在恢复并登录后补执行，实际执行时间将如实记入历史。",
            TaskId = taskId,
            TaskName = taskName,
            PlannedUtc = plannedUtc
        };
    }

    private async Task<ElevatedActionResult> ScheduleTimedBlockAsync(
        ElevatedAction action,
        string source,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        ValidatedTarget target;
        try { target = ValidateTargetForBlock(action.TargetKind, action.Target); }
        catch (TargetValidationException ex) { return Failure(action, ex.Message, source, correlationId); }

        var pending = GetPendingTasksForTarget(target);
        if (pending.Count > 0)
            return Failure(action, "该对象已有待执行或正在执行的定时任务。请先取消现有任务。", source, correlationId);

        var readiness = CheckFirewallReadyForBlock();
        if (readiness is not null)
            return Failure(action, readiness, source, correlationId);

        StateReadResultGuard(out var state, out var stateError);
        if (stateError is not null) return Failure(action, stateError, source, correlationId);

        var requestedDirections = action.Directions.ToFirewallDirections().ToList();
        var active = FindActiveRulesForTarget(state, target)
            .Where(r => requestedDirections.Contains(r.Direction))
            .ToList();
        if (active.Count > 0)
        {
            var inspections = _firewall.InspectRules(active).Inspections;
            foreach (var rule in active)
            {
                inspections.TryGetValue(rule.RuleId, out var inspection);
                if (inspection is null || inspection.State == RuleInspectionState.Unknown)
                    return Failure(action, "无法核实已有规则状态，未创建限时禁止任务。", source, correlationId);
                if (inspection.State == RuleInspectionState.Mismatched)
                    return Failure(action, $"该对象已有受外部修改的规则：{inspection.Detail} 请先处理。", source, correlationId);
                if (inspection.State == RuleInspectionState.Verified)
                    return Failure(action, "该对象当前已被本工具阻断。限时禁止不会接管已有永久阻断，请先解除现有规则，或改用“延迟解除”。", source, correlationId);
            }
        }

        var delay = action.DelayMinutes!.Value;
        var now = _clock.UtcNow;
        var plannedUtc = now.AddMinutes(delay);
        var taskId = Guid.NewGuid().ToString("N");
        var taskName = Scheduling.TaskNamePolicy.ForTask(taskId);
        var builds = BuildRulePlans(target, action.Directions.ToFirewallDirections(), now, WindowsPrivilege.CurrentUserName());
        var taskRecord = BuildScheduledTask(taskId, taskName, ScheduledMode.TimedBlock, ScheduledExecutionAction.Unblock,
            target, action.Directions, builds.Select(b => b.Record).ToList(), now, plannedUtc, correlationId);

        // Register the automatic restoration before applying the block, so a
        // crash after the firewall rule is created cannot leave it unmanaged.
        try
        {
            await _scheduler.RegisterAsync(
                taskName,
                $"--execute-task={taskId}",
                plannedUtc,
                BuildScheduleDescription("限时禁止自动解除", target),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Error("Schedule", "注册限时禁止任务失败", ex);
            return Failure(action, $"无法注册 Windows 自动解除任务，因此没有创建阻断规则：{ex.Message}", source, correlationId, ex.ToString());
        }

        var created = false;
        try
        {
            var inspectionsAfter = _firewall.CreateRules(builds.Select(b => b.Definition).ToList());
            if (inspectionsAfter.Any(i => i.State != RuleInspectionState.Verified))
                throw new Firewall.FirewallOperationException("规则创建后的防火墙验证未全部通过。");
            created = true;

            _store.Mutate(s =>
            {
                foreach (var build in builds)
                    s.Rules.Add(build.Record);
                s.Tasks.Add(taskRecord);
                s.Events.Add(NewEvent(
                    "限时禁止", target, OperationOutcome.Success,
                    $"已立即阻断，并计划于 {TimeDisplay.LocalDateTime(plannedUtc)} 自动解除本工具创建的 {builds.Count} 条规则。",
                    string.Join(Environment.NewLine, builds.Select(b => $"{b.Record.FirewallRuleName}（{b.Record.Direction.ToShortChinese()}）")),
                    source, correlationId, ruleIds: builds.Select(b => b.Record.RuleId).ToList(), taskId: taskId,
                    plannedUtc: plannedUtc, actualUtc: now));
            });
        }
        catch (Exception ex)
        {
            _log.Error("Schedule", "限时禁止创建或保存失败，开始回滚", ex);
            if (created)
            {
                var cleanup = CleanupCreatedRules(builds);
                if (cleanup.Count > 0)
                    TryLogFailureEvent("限时禁止", target, source, correlationId, "规则回滚失败：" + string.Join("；", cleanup), taskId);
            }
            await TryDeleteTaskAsync(taskName).ConfigureAwait(false);
            return Failure(action, $"限时禁止设置失败，阻断规则已回滚（若回滚无误）：{ex.Message}", source, correlationId, ex.ToString());
        }

        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = true,
            Outcome = OperationOutcome.Success,
            Message = $"现在已禁止该对象的{DirectionText.ToChinese(action.Directions)}网络访问，并将在 {delay} 分钟后（{TimeDisplay.LocalDateTime(plannedUtc)}）自动解除本工具创建的 {builds.Count} 条规则。系统休眠或关机时将在恢复并登录后补执行，实际执行时间会如实记录。",
            RuleIds = builds.Select(b => b.Record.RuleId).ToList(),
            TaskId = taskId,
            TaskName = taskName,
            PlannedUtc = plannedUtc
        };
    }

    private async Task<ElevatedActionResult> ScheduleDelayedUnblockAsync(
        ElevatedAction action,
        string source,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        ValidatedTarget target;
        try { target = ValidateExistingTarget(action.TargetKind, action.Target); }
        catch (TargetValidationException ex) { return Failure(action, ex.Message, source, correlationId); }

        var pending = GetPendingTasksForTarget(target);
        if (pending.Count > 0)
            return Failure(action, "该对象已有待执行或正在执行的定时任务。请先取消现有任务。", source, correlationId);

        StateReadResultGuard(out var state, out var stateError);
        if (stateError is not null) return Failure(action, stateError, source, correlationId);

        var requested = action.Directions.ToFirewallDirections().ToList();
        var active = FindActiveRulesForTarget(state, target)
            .Where(r => requested.Count == 0 || requested.Contains(r.Direction))
            .ToList();
        if (active.Count == 0)
            return Failure(action, "没有找到该对象由本工具创建的有效阻断规则，无法安排延迟解除。", source, correlationId);

        var inspections = _firewall.InspectRules(active).Inspections;
        var invalid = new List<string>();
        var verified = new List<ManagedRuleRecord>();
        foreach (var rule in active)
        {
            inspections.TryGetValue(rule.RuleId, out var inspection);
            if (inspection?.State == RuleInspectionState.Verified)
                verified.Add(rule);
            else
                invalid.Add($"{rule.FirewallRuleName}：{inspection?.Detail ?? "无法读取规则状态"}");
        }
        if (invalid.Count > 0)
            return Failure(action, "存在状态不一致的本工具规则，未安排自动解除。请先在规则管理中检查：" + string.Join("；", invalid), source, correlationId);
        if (verified.Count == 0)
            return Failure(action, "没有可用于延迟解除的有效规则。", source, correlationId);

        var delay = action.DelayMinutes!.Value;
        var now = _clock.UtcNow;
        var plannedUtc = now.AddMinutes(delay);
        var taskId = Guid.NewGuid().ToString("N");
        var taskName = Scheduling.TaskNamePolicy.ForTask(taskId);
        var builds = BuildPlansFromRecords(verified);
        var record = BuildScheduledTask(taskId, taskName, ScheduledMode.DelayedUnblock, ScheduledExecutionAction.Unblock,
            target, action.Directions, verified, now, plannedUtc, correlationId);

        try
        {
            await _scheduler.RegisterAsync(
                taskName,
                $"--execute-task={taskId}",
                plannedUtc,
                BuildScheduleDescription("延迟解除", target),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Error("Schedule", "注册延迟解除任务失败", ex);
            TryLogFailureEvent("延迟解除", target, source, correlationId, ex.Message, taskId);
            return Failure(action, $"无法注册 Windows 计划任务：{ex.Message}", source, correlationId, ex.ToString());
        }

        try
        {
            _store.Mutate(s =>
            {
                s.Tasks.Add(record);
                s.Events.Add(NewEvent(
                    "延迟解除", target, OperationOutcome.Success,
                    $"已创建延迟解除任务，计划于 {TimeDisplay.LocalDateTime(plannedUtc)} 解除本工具创建的 {verified.Count} 条阻断规则。",
                    null,
                    source, correlationId, ruleIds: verified.Select(r => r.RuleId).ToList(), taskId: taskId, plannedUtc: plannedUtc));
            });
        }
        catch (Exception ex)
        {
            await TryDeleteTaskAsync(taskName).ConfigureAwait(false);
            _log.Error("Schedule", "延迟解除任务状态保存失败", ex);
            return Failure(action, $"状态数据保存失败，计划任务已回滚：{ex.Message}", source, correlationId, ex.ToString());
        }

        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = true,
            Outcome = OperationOutcome.Success,
            Message = $"已创建延迟解除任务。将在 {delay} 分钟后（{TimeDisplay.LocalDateTime(plannedUtc)}）解除本工具创建的 {verified.Count} 条阻断规则。",
            RuleIds = verified.Select(r => r.RuleId).ToList(),
            TaskId = taskId,
            TaskName = taskName,
            PlannedUtc = plannedUtc
        };
    }

    private ScheduledTaskRecord BuildScheduledTask(
        string taskId,
        string taskName,
        ScheduledMode mode,
        ScheduledExecutionAction executionAction,
        ValidatedTarget target,
        BlockDirections directions,
        IReadOnlyList<ManagedRuleRecord> rules,
        DateTimeOffset createdUtc,
        DateTimeOffset plannedUtc,
        string? correlationId)
    {
        return new ScheduledTaskRecord
        {
            TaskId = taskId,
            Mode = mode,
            ExecutionAction = executionAction,
            Status = ScheduledTaskStatus.Pending,
            TargetKind = target.Kind,
            Target = target.Value,
            DisplayTarget = target.Display,
            Directions = directions,
            PlannedRules = rules.Select(r => new PlannedRule
            {
                RuleId = r.RuleId,
                FirewallRuleName = r.FirewallRuleName,
                Direction = r.Direction
            }).ToList(),
            ScheduledTaskName = taskName,
            CreatedUtc = createdUtc,
            PlannedUtc = plannedUtc,
            CreatedBy = WindowsPrivilege.CurrentUserName(),
            CorrelationId = correlationId
        };
    }

    private static string BuildScheduleDescription(string action, ValidatedTarget target)
    {
        var text = $"网络访问管理器 · {action} · {target.Kind switch { RuleTargetKind.Program => "程序", RuleTargetKind.Ethernet => "以太网", _ => "网络目标" }}：{target.Display}";
        return text.Length > 500 ? text[..500] + "…" : text;
    }

    private async Task<string?> TryDeleteTaskAsync(string taskName)
    {
        try
        {
            await _scheduler.DeleteAsync(taskName, CancellationToken.None).ConfigureAwait(false);
            return null;
        }
        catch (Exception ex)
        {
            _log.Warn("Schedule", $"清理计划任务 {taskName} 失败：{ex.Message}");
            return ex.Message;
        }
    }

    public async Task<ScheduledExecutionResult> ExecuteScheduledTaskAsync(
        string taskId,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParseExact(taskId, "N", out _))
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = "任务 ID 无效。" };

        if (!_firewall.IsElevated)
        {
            var error = "计划任务执行时没有管理员权限，无法修改 Windows 防火墙。请以管理员账户重新安排，或从主程序重新确认操作。";
            MarkTaskFailedWithoutPrivilege(taskId, error);
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = error };
        }

        OperationFileLock operationLock;
        try
        {
            operationLock = OperationFileLock.Acquire(_store.Paths, _log);
        }
        catch (Exception ex)
        {
            _log.Error("ScheduledTask", "计划任务获取操作锁失败", ex);
            MarkTaskFailedWithoutPrivilege(taskId, $"无法获取操作锁：{ex.Message}");
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = ex.Message };
        }

        using (operationLock)
        {
            ScheduledTaskRecord? task;
            try
            {
                var read = _store.ReadState();
                task = read.State.Tasks.FirstOrDefault(t => t.TaskId == taskId);
            }
            catch (Exception ex)
            {
                _log.Error("ScheduledTask", "读取定时任务状态失败", ex);
                return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = $"无法读取任务状态：{ex.Message}" };
            }

            if (task is null)
            {
                _log.Warn("ScheduledTask", $"计划任务 {taskId} 在状态库中不存在，未执行任何操作。");
                return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = "找不到对应的定时任务记录。" };
            }

            if (task.Status != ScheduledTaskStatus.Pending)
            {
                _log.Info("ScheduledTask", $"计划任务 {taskId} 状态为 {task.Status}，忽略本次触发。");
                return new ScheduledExecutionResult { Success = true, ExitCode = 0, Message = $"任务当前状态为 {task.StatusText}，不会重复执行。" };
            }

            if (!Scheduling.TaskNamePolicy.IsValid(task.ScheduledTaskName))
            {
                var reason = "任务记录中的系统计划任务名称无效，未执行。";
                CompleteTask(taskId, ScheduledTaskStatus.Failed, reason);
                return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = reason };
            }

            try
            {
                var started = _clock.UtcNow;
                var claimed = _store.Mutate(state =>
                {
                    var current = state.Tasks.FirstOrDefault(t => t.TaskId == taskId);
                    if (current is null || current.Status != ScheduledTaskStatus.Pending)
                        return false;
                    current.Status = ScheduledTaskStatus.Running;
                    current.StartedUtc = started;
                    current.LastObservedUtc = started;
                    return true;
                });
                if (!claimed)
                    return new ScheduledExecutionResult { Success = true, ExitCode = 0, Message = "任务状态已变化，本次不执行。" };

                ScheduledExecutionResult executionResult;
                if (task.ExecutionAction == ScheduledExecutionAction.Block)
                    executionResult = ExecuteScheduledBlock(task);
                else if (task.ExecutionAction == ScheduledExecutionAction.EthernetDisable)
                    executionResult = ExecuteScheduledEthernetDisable(task);
                else
                    executionResult = ExecuteScheduledUnblock(task);

                // A one-shot task is exhausted after this run. Best-effort
                // removal avoids leaving a runnable historical task behind.
                var cleanupError = await TryDeleteTaskAsync(task.ScheduledTaskName).ConfigureAwait(false);
                if (cleanupError is not null)
                    _log.Warn("ScheduledTask", $"执行后清理系统计划任务失败：{cleanupError}");
                return executionResult;
            }
            catch (Exception ex)
            {
                _log.Error("ScheduledTask", "定时任务执行异常", ex);
                CompleteTask(taskId, ScheduledTaskStatus.Failed, $"执行时发生异常：{ex.Message}");
                return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = ex.Message };
            }
        }
    }

    private ScheduledExecutionResult ExecuteScheduledBlock(ScheduledTaskRecord task)
    {
        ValidatedTarget target;
        try
        {
            target = ValidateTargetForBlock(task.TargetKind, task.Target);
        }
        catch (TargetValidationException ex)
        {
            CompleteTask(task.TaskId, ScheduledTaskStatus.Failed, "执行延迟禁止失败：" + ex.Message);
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = ex.Message };
        }

        var readiness = CheckFirewallReadyForBlock();
        if (readiness is not null)
        {
            CompleteTask(task.TaskId, ScheduledTaskStatus.Failed, "执行延迟禁止失败：" + readiness);
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = readiness };
        }

        var directions = task.PlannedRules.Select(r => r.Direction).Distinct().ToList();
        if (directions.Count == 0 || task.PlannedRules.Any(p => !IsPlannedRuleValid(p, task.TargetKind, target.Value)))
        {
            var reason = "任务中的规则计划无效或已被破坏，未创建规则。";
            CompleteTask(task.TaskId, ScheduledTaskStatus.Failed, reason);
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = reason };
        }

        var state = _store.ReadState().State;
        var existing = FindActiveRulesForTarget(state, target)
            .Where(r => directions.Contains(r.Direction))
            .ToList();
        if (existing.Count > 0)
        {
            var inspections = _firewall.InspectRules(existing).Inspections;
            var allVerified = existing.All(r => inspections.TryGetValue(r.RuleId, out var i) && i.State == RuleInspectionState.Verified);
            if (allVerified && existing.Select(r => r.Direction).Distinct().Count() == directions.Count)
            {
                var message = "执行时发现目标已由本工具阻止，本次未重复创建规则。";
                CompleteTask(task.TaskId, ScheduledTaskStatus.Succeeded, message, isInfoOnly: true);
                return new ScheduledExecutionResult { Success = true, ExitCode = 0, Message = message };
            }
            var reason = "执行延迟禁止时发现相同目标已有其他本工具规则或状态不一致，未重复创建。";
            CompleteTask(task.TaskId, ScheduledTaskStatus.Failed, reason);
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = reason };
        }

        var now = _clock.UtcNow;
        var builds = BuildExecutionRules(task, target, now);
        var created = false;
        try
        {
            var inspections = _firewall.CreateRules(builds.Select(b => b.Definition).ToList());
            if (inspections.Any(i => i.State != RuleInspectionState.Verified))
                throw new Firewall.FirewallOperationException("创建的规则未通过防火墙验证。");
            created = true;
            _store.Mutate(s =>
            {
                foreach (var build in builds)
                    s.Rules.Add(build.Record);
                var stored = s.Tasks.First(t => t.TaskId == task.TaskId);
                stored.Status = ScheduledTaskStatus.Succeeded;
                stored.CompletedUtc = now;
                stored.LastObservedUtc = now;
                stored.ResultMessage = $"已按计划创建 {builds.Count} 条阻断规则。实际执行时间 {TimeDisplay.LocalDateTime(now)}。";
                s.Events.Add(NewEvent(
                    "延迟禁止（执行）", target, OperationOutcome.Success, stored.ResultMessage,
                    "由 Windows 任务计划程序触发。",
                    "系统计划任务", task.CorrelationId,
                    ruleIds: builds.Select(b => b.Record.RuleId).ToList(), taskId: task.TaskId,
                    plannedUtc: task.PlannedUtc, actualUtc: now));
            });
            return new ScheduledExecutionResult { Success = true, ExitCode = 0, Message = "延迟禁止已执行并记录。" };
        }
        catch (Exception ex)
        {
            _log.Error("ScheduledTask", "执行延迟禁止失败", ex);
            if (created)
            {
                var cleanup = CleanupCreatedRules(builds);
                if (cleanup.Count > 0) _log.Error("ScheduledTask", "延迟禁止失败后的规则回滚也失败：" + string.Join("；", cleanup));
            }
            CompleteTask(task.TaskId, ScheduledTaskStatus.Failed, $"执行失败：{ex.Message}", target: target);
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = ex.Message };
        }
    }

    private ScheduledExecutionResult ExecuteScheduledUnblock(ScheduledTaskRecord task)
    {
        StateReadResultGuard(out var state, out var readError);
        if (readError is not null)
        {
            CompleteTask(task.TaskId, ScheduledTaskStatus.Failed, "执行自动解除失败：" + readError);
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = readError };
        }

        var records = state.Rules
            .Where(r => task.PlannedRules.Any(p => string.Equals(p.RuleId, r.RuleId, StringComparison.OrdinalIgnoreCase)))
            .ToList();
        var inspections = records.Count > 0
            ? _firewall.InspectRules(records).Inspections
            : new Dictionary<string, FirewallRuleInspection>(StringComparer.OrdinalIgnoreCase);

        var removed = new List<ManagedRuleRecord>();
        var missing = new List<ManagedRuleRecord>();
        var failed = new List<string>();
        foreach (var planned in task.PlannedRules)
        {
            var record = records.FirstOrDefault(r => string.Equals(r.RuleId, planned.RuleId, StringComparison.OrdinalIgnoreCase));
            if (record is null)
            {
                missing.Add(new ManagedRuleRecord { RuleId = planned.RuleId, FirewallRuleName = planned.FirewallRuleName, Direction = planned.Direction, Target = task.Target });
                continue;
            }
            if (record.Status != ManagedRuleStatus.Active)
            {
                missing.Add(record);
                continue;
            }
            inspections.TryGetValue(record.RuleId, out var inspection);
            if (inspection is null || inspection.State == RuleInspectionState.Unknown)
            {
                failed.Add($"{record.RuleId}：{inspection?.Detail ?? "无法读取规则状态"}");
                continue;
            }
            if (inspection.State == RuleInspectionState.Missing)
            {
                missing.Add(record);
                continue;
            }
            if (!inspection.IdentityMatches)
            {
                failed.Add($"{record.RuleId}：同名规则身份不匹配，拒绝删除");
                continue;
            }
            try
            {
                _firewall.RemoveRule(record.FirewallRuleName, record.RuleId);
                removed.Add(record);
            }
            catch (Exception ex)
            {
                failed.Add($"{record.RuleId}：{ex.Message}");
            }
        }

        var now = _clock.UtcNow;
        var allExpectedPresentAndRemoved = missing.Count == 0 && failed.Count == 0 && removed.Count == task.PlannedRules.Count;
        var status = allExpectedPresentAndRemoved ? ScheduledTaskStatus.Succeeded : ScheduledTaskStatus.Failed;
        var summary = allExpectedPresentAndRemoved
            ? $"已按计划解除本工具创建的 {removed.Count} 条规则。实际执行时间 {TimeDisplay.LocalDateTime(now)}。"
            : $"自动解除未完全成功：已解除 {removed.Count} 条，已不存在 {missing.Count} 条，失败 {failed.Count} 条。{string.Join("；", failed)}";
        try
        {
            _store.Mutate(s =>
            {
                foreach (var r in removed)
                {
                    var stored = s.Rules.FirstOrDefault(x => x.RuleId == r.RuleId);
                    if (stored is not null)
                    {
                        stored.Status = ManagedRuleStatus.RemovedByUser;
                        stored.VerifiedUtc = now;
                        stored.Note = "由定时自动解除任务删除。";
                    }
                }
                foreach (var r in missing)
                {
                    var stored = s.Rules.FirstOrDefault(x => x.RuleId == r.RuleId);
                    if (stored is not null)
                    {
                        stored.Status = ManagedRuleStatus.RemovedExternally;
                        stored.VerifiedUtc = now;
                        stored.Note = "自动解除执行时发现规则已不存在。";
                    }
                }
                var storedTask = s.Tasks.First(t => t.TaskId == task.TaskId);
                storedTask.Status = status;
                storedTask.CompletedUtc = now;
                storedTask.LastObservedUtc = now;
                storedTask.ResultMessage = summary;
                if (!allExpectedPresentAndRemoved) storedTask.FailureReason = summary;
                s.Events.Add(NewEvent(
                    allExpectedPresentAndRemoved ? "自动解除（执行）" : "自动解除（执行失败）",
                    new ValidatedTarget(task.TargetKind, task.Target, task.DisplayTarget),
                    allExpectedPresentAndRemoved ? OperationOutcome.Success : OperationOutcome.Warning,
                    summary,
                    string.Join(Environment.NewLine, failed.Concat(missing.Select(m => $"已不存在：{m.FirewallRuleName}"))),
                    "系统计划任务", task.CorrelationId,
                    ruleIds: removed.Select(r => r.RuleId).ToList(), taskId: task.TaskId,
                    plannedUtc: task.PlannedUtc, actualUtc: now));
            });
        }
        catch (Exception ex)
        {
            _log.Error("ScheduledTask", "自动解除后保存状态失败", ex);
            return new ScheduledExecutionResult { Success = false, ExitCode = 2, Message = $"规则已处理，但状态保存失败：{ex.Message}" };
        }

        return new ScheduledExecutionResult
        {
            Success = allExpectedPresentAndRemoved,
            ExitCode = allExpectedPresentAndRemoved ? 0 : 2,
            Message = summary
        };
    }

    private bool IsPlannedRuleValid(PlannedRule planned, RuleTargetKind targetKind, string target)
    {
        if (!Guid.TryParseExact(planned.RuleId, "N", out _)) return false;
        if (!string.Equals(planned.FirewallRuleName, Firewall.FirewallRuleMetadata.BuildRuleName(planned.RuleId, planned.Direction), StringComparison.Ordinal))
            return false;
        return Enum.IsDefined(planned.Direction) && Enum.IsDefined(targetKind);
    }

    private List<RuleBuild> BuildExecutionRules(ScheduledTaskRecord task, ValidatedTarget target, DateTimeOffset now)
    {
        var ownerSid = WindowsPrivilege.CurrentUserSid();
        var builds = new List<RuleBuild>();
        foreach (var planned in task.PlannedRules)
        {
            var metadata = Firewall.FirewallRuleMetadata.Create(
                planned.RuleId, planned.Direction, target.Kind, target.Value, ownerSid, task.CreatedUtc);
            var description = metadata.ToDescription();
            builds.Add(new RuleBuild(
                new RuleDefinition
                {
                    RuleId = planned.RuleId,
                    FirewallRuleName = planned.FirewallRuleName,
                    Description = description,
                    TargetKind = target.Kind,
                    Target = target.Value,
                    Direction = planned.Direction
                },
                new ManagedRuleRecord
                {
                    RuleId = planned.RuleId,
                    TargetKind = target.Kind,
                    Target = target.Value,
                    DisplayTarget = target.Display,
                    Direction = planned.Direction,
                    FirewallRuleName = planned.FirewallRuleName,
                    Description = description,
                    Status = ManagedRuleStatus.Active,
                    CreatedUtc = now,
                    CreatedBy = task.CreatedBy,
                    OperationGroupId = task.TaskId,
                    VerifiedUtc = now
                }));
        }
        return builds;
    }

    private void CompleteTask(
        string taskId,
        ScheduledTaskStatus status,
        string message,
        bool isInfoOnly = false,
        ValidatedTarget? target = null)
    {
        var now = _clock.UtcNow;
        try
        {
            _store.Mutate(s =>
            {
                var task = s.Tasks.FirstOrDefault(t => t.TaskId == taskId);
                if (task is null) return;
                if (task.Status is ScheduledTaskStatus.Succeeded or ScheduledTaskStatus.Cancelled) return;
                task.Status = status;
                task.CompletedUtc = now;
                task.LastObservedUtc = now;
                task.ResultMessage = message;
                if (status == ScheduledTaskStatus.Failed) task.FailureReason = message;
                s.Events.Add(NewEvent(
                    "定时任务执行",
                    target ?? new ValidatedTarget(task.TargetKind, task.Target, task.DisplayTarget),
                    isInfoOnly ? OperationOutcome.Info : status == ScheduledTaskStatus.Succeeded ? OperationOutcome.Success : OperationOutcome.Failure,
                    message, null, "系统计划任务", task.CorrelationId,
                    ruleIds: task.PlannedRules.Select(p => p.RuleId).ToList(), taskId: taskId,
                    plannedUtc: task.PlannedUtc, actualUtc: now));
            });
        }
        catch (Exception ex)
        {
            _log.Error("ScheduledTask", $"更新任务 {taskId} 最终状态失败", ex);
        }
    }

    private void MarkTaskFailedWithoutPrivilege(string taskId, string message)
    {
        try
        {
            var read = _store.ReadState();
            var task = read.State.Tasks.FirstOrDefault(t => t.TaskId == taskId);
            if (task is null || task.Status != ScheduledTaskStatus.Pending) return;
            CompleteTask(taskId, ScheduledTaskStatus.Failed, message);
        }
        catch (Exception ex)
        {
            _log.Error("ScheduledTask", "无权限时记录任务失败状态失败", ex);
        }
    }
}
