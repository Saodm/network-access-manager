using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.Core.Operations;

public sealed partial class NetworkControlService
{
    private async Task<ElevatedActionResult> ExecuteUnblockTargetAsync(
        ElevatedAction action,
        string source,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        ValidatedTarget target;
        try { target = ValidateExistingTarget(action.TargetKind, action.Target); }
        catch (TargetValidationException ex) { return Failure(action, ex.Message, source, correlationId); }

        StateReadResultGuard(out var state, out var readError);
        if (readError is not null) return Failure(action, readError, source, correlationId);

        var active = FindActiveRulesForTarget(state, target);
        if (active.Count == 0)
        {
            var message = "没有找到该对象由本工具创建且仍处于有效状态的阻断规则，未修改 Windows 防火墙。";
            SafeAppendEvent(NewEvent("解除禁止", target, OperationOutcome.Info, message, null, source, correlationId));
            return new ElevatedActionResult
            {
                ActionId = action.ActionId,
                Success = true,
                Outcome = OperationOutcome.Info,
                Message = message,
                RuleIds = Array.Empty<string>().ToList()
            };
        }

        var removal = RemoveRulesCore(active);
        var now = _clock.UtcNow;
        var affectedIds = removal.Removed.Select(r => r.RuleId)
            .Concat(removal.Missing.Select(r => r.RuleId))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var tasksToCancel = state.Tasks
            .Where(t => t.Status == ScheduledTaskStatus.Pending)
            .Where(t => t.PlannedRules.Count > 0 && t.PlannedRules.All(p => affectedIds.Contains(p.RuleId)))
            .ToList();

        var detailParts = new List<string>();
        if (removal.Missing.Count > 0)
            detailParts.Add("已不存在：" + string.Join("、", removal.Missing.Select(r => r.FirewallRuleName)));
        if (removal.Failed.Count > 0)
            detailParts.Add("失败：" + string.Join("；", removal.Failed));
        if (tasksToCancel.Count > 0)
            detailParts.Add("已同时取消关联定时任务：" + string.Join("、", tasksToCancel.Select(t => t.TaskId)));

        try
        {
            _store.Mutate(s =>
            {
                foreach (var record in removal.Removed)
                {
                    var stored = s.Rules.FirstOrDefault(r => r.RuleId == record.RuleId);
                    if (stored is null) continue;
                    stored.Status = ManagedRuleStatus.RemovedByUser;
                    stored.VerifiedUtc = now;
                    stored.Note = "由用户在“解除禁止”操作中删除。";
                }
                foreach (var record in removal.Missing)
                {
                    var stored = s.Rules.FirstOrDefault(r => r.RuleId == record.RuleId);
                    if (stored is null) continue;
                    stored.Status = ManagedRuleStatus.RemovedExternally;
                    stored.VerifiedUtc = now;
                    stored.Note = "解除操作时发现规则已不在 Windows 防火墙中。";
                }
                foreach (var task in tasksToCancel)
                {
                    var storedTask = s.Tasks.FirstOrDefault(t => t.TaskId == task.TaskId);
                    if (storedTask is null || storedTask.Status != ScheduledTaskStatus.Pending) continue;
                    storedTask.Status = ScheduledTaskStatus.Cancelled;
                    storedTask.CompletedUtc = now;
                    storedTask.LastObservedUtc = now;
                    storedTask.ResultMessage = "因用户手动解除相关阻断规则，任务已被取消。";
                    s.Events.Add(NewEvent(
                        "取消定时任务（随规则解除）",
                        new ValidatedTarget(storedTask.TargetKind, storedTask.Target, storedTask.DisplayTarget),
                        OperationOutcome.Info,
                        storedTask.ResultMessage,
                        "未到计划时间，规则已由用户手动解除。",
                        source, correlationId,
                        taskId: storedTask.TaskId,
                        plannedUtc: storedTask.PlannedUtc,
                        actualUtc: now));
                }

                var removedCount = removal.Removed.Count;
                var missingCount = removal.Missing.Count;
                var failedCount = removal.Failed.Count;
                string message;
                OperationOutcome outcome;
                if (failedCount == 0)
                {
                    message = $"已解除本工具创建的 {removedCount} 条阻断规则。";
                    if (missingCount > 0)
                        message += $" 另有 {missingCount} 条规则在执行前已不存在（可能被外部修改），已同步状态。";
                    if (tasksToCancel.Count > 0)
                        message += $" 已同时取消 {tasksToCancel.Count} 个尚未执行的关联定时任务。";
                    outcome = missingCount > 0 ? OperationOutcome.Warning : OperationOutcome.Success;
                }
                else
                {
                    message = $"部分解除：成功 {removedCount} 条，已不存在 {missingCount} 条，失败 {failedCount} 条。仍可能有规则在生效，请检查。";
                    outcome = OperationOutcome.Failure;
                }

                s.Events.Add(NewEvent(
                    "解除禁止", target, outcome, message, string.Join(Environment.NewLine, detailParts),
                    source, correlationId,
                    ruleIds: removal.Removed.Select(r => r.RuleId).ToList(),
                    actualUtc: now));
            });
        }
        catch (Exception ex)
        {
            _log.Error("Unblock", "解除规则后保存状态失败", ex);
            return Failure(action, $"Windows 防火墙规则可能已经变更，但状态数据保存失败：{ex.Message}。请刷新检查。", source, correlationId, ex.ToString());
        }

        var schedulerCleanupWarnings = new List<string>();
        foreach (var task in tasksToCancel)
        {
            var error = await TryDeleteTaskAsync(task.ScheduledTaskName).ConfigureAwait(false);
            if (error is not null) schedulerCleanupWarnings.Add($"{task.TaskId}：{error}");
        }
        if (schedulerCleanupWarnings.Count > 0)
        {
            var warning = "状态已取消，但以下 Windows 计划任务记录未能删除；即使再次触发也会读取到已取消状态并退出：" + string.Join("；", schedulerCleanupWarnings);
            _log.Warn("Unblock", warning);
            SafeAppendEvent(NewEvent("清理计划任务记录", target, OperationOutcome.Warning, warning, null, source, correlationId));
        }

        var success = removal.Failed.Count == 0;
        var finalMessage = success
            ? $"已解除本工具创建的 {removal.Removed.Count} 条阻断规则。"
            : $"部分规则解除失败，仍有本工具规则可能生效。失败：{string.Join("；", removal.Failed)}";
        if (removal.Missing.Count > 0)
            finalMessage += $" 另有 {removal.Missing.Count} 条在操作时已不存在，状态已据实更新。";
        if (tasksToCancel.Count > 0)
            finalMessage += $" 已取消 {tasksToCancel.Count} 个关联定时任务。";
        if (schedulerCleanupWarnings.Count > 0)
            finalMessage += " 部分 Windows 计划任务记录未能删除；逻辑取消已生效，后续触发不会修改规则。";

        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = success,
            Outcome = success
                ? (removal.Missing.Count > 0 || schedulerCleanupWarnings.Count > 0 ? OperationOutcome.Warning : OperationOutcome.Success)
                : OperationOutcome.Failure,
            Message = finalMessage,
            Detail = detailParts.Count == 0 ? null : string.Join(Environment.NewLine, detailParts),
            RuleIds = removal.Removed.Select(r => r.RuleId).ToList()
        };
    }

    private async Task<ElevatedActionResult> ExecuteCancelScheduledTaskAsync(
        ElevatedAction action,
        string source,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        var taskId = action.TaskId!;
        StateReadResultGuard(out var state, out var readError);
        if (readError is not null) return Failure(action, readError, source, correlationId);

        var task = state.Tasks.FirstOrDefault(t => t.TaskId == taskId);
        if (task is null)
            return Failure(action, "找不到要取消的定时任务记录。", source, correlationId);
        if (task.Status == ScheduledTaskStatus.Running)
            return Failure(action, "该任务正在执行，无法取消。请等待执行结果。", source, correlationId);
        if (task.Status != ScheduledTaskStatus.Pending)
            return Failure(action, $"该任务当前状态为“{task.StatusText}”，不能取消。", source, correlationId);

        var now = _clock.UtcNow;
        try
        {
            _store.Mutate(s =>
            {
                var stored = s.Tasks.FirstOrDefault(t => t.TaskId == taskId);
                if (stored is null || stored.Status != ScheduledTaskStatus.Pending)
                    throw new OperationBusyException("任务状态在取消过程中发生变化。");
                stored.Status = ScheduledTaskStatus.Cancelled;
                stored.CompletedUtc = now;
                stored.LastObservedUtc = now;
                stored.ResultMessage = "用户取消了此定时任务。";
                s.Events.Add(NewEvent(
                    "取消定时任务",
                    new ValidatedTarget(stored.TargetKind, stored.Target, stored.DisplayTarget),
                    OperationOutcome.Success,
                    "用户取消了此定时任务；后续系统触发不会再执行任何规则操作。",
                    "取消动作先写入逻辑状态，再尝试删除 Windows 计划任务记录。",
                    source, correlationId,
                    taskId: taskId,
                    plannedUtc: stored.PlannedUtc,
                    actualUtc: now));
            });
        }
        catch (Exception ex)
        {
            _log.Error("Cancel", "取消任务状态保存失败", ex);
            return Failure(action, $"取消未完成，任务状态未能安全保存：{ex.Message}", source, correlationId, ex.ToString());
        }

        var schedulerError = await TryDeleteTaskAsync(task.ScheduledTaskName).ConfigureAwait(false);
        var warnings = new List<string>();
        var failures = new List<string>();
        if (schedulerError is not null)
            warnings.Add($"Windows 计划任务记录未能删除：{schedulerError}。但逻辑状态已取消，后续触发会直接退出并且不会修改规则。");

        var unblockRemoved = 0;
        var unblockMissing = 0;
        if (action.UnblockRulesOnCancel && task.PlannedRules.Count > 0)
        {
            StateReadResultGuard(out var latestState, out var latestError);
            if (latestError is not null)
            {
                failures.Add(latestError);
            }
            else
            {
                var records = latestState.Rules
                    .Where(r => task.PlannedRules.Any(p => string.Equals(p.RuleId, r.RuleId, StringComparison.OrdinalIgnoreCase)))
                    .Where(r => r.Status == ManagedRuleStatus.Active)
                    .ToList();
                if (records.Count > 0)
                {
                    var removal = RemoveRulesCore(records);
                    unblockRemoved = removal.Removed.Count;
                    unblockMissing = removal.Missing.Count;
                    if (removal.Failed.Count > 0)
                        failures.Add("同时解除规则失败：" + string.Join("；", removal.Failed));
                    try
                    {
                        _store.Mutate(s =>
                        {
                            foreach (var record in removal.Removed)
                            {
                                var stored = s.Rules.FirstOrDefault(r => r.RuleId == record.RuleId);
                                if (stored is null) continue;
                                stored.Status = ManagedRuleStatus.RemovedByUser;
                                stored.VerifiedUtc = _clock.UtcNow;
                                stored.Note = "取消限时/延迟任务时立即解除。";
                            }
                            foreach (var record in removal.Missing)
                            {
                                var stored = s.Rules.FirstOrDefault(r => r.RuleId == record.RuleId);
                                if (stored is null) continue;
                                stored.Status = ManagedRuleStatus.RemovedExternally;
                                stored.VerifiedUtc = _clock.UtcNow;
                                stored.Note = "取消任务并解除规则时发现规则已不存在。";
                            }
                            var storedTask = s.Tasks.FirstOrDefault(t => t.TaskId == taskId);
                            if (storedTask is not null)
                            {
                                storedTask.ResultMessage = BuildCancelResultMessage(
                                    schedulerError is null,
                                    removal.Removed.Count,
                                    removal.Missing.Count,
                                    removal.Failed.Count);
                                storedTask.FailureReason = removal.Failed.Count > 0
                                    ? string.Join("；", removal.Failed)
                                    : null;
                            }
                            s.Events.Add(NewEvent(
                                "取消任务并解除规则",
                                new ValidatedTarget(task.TargetKind, task.Target, task.DisplayTarget),
                                removal.Failed.Count == 0 ? OperationOutcome.Success : OperationOutcome.Failure,
                                BuildCancelResultMessage(schedulerError is null, removal.Removed.Count, removal.Missing.Count, removal.Failed.Count),
                                string.Join(Environment.NewLine, removal.Failed),
                                source, correlationId,
                                ruleIds: removal.Removed.Select(r => r.RuleId).ToList(),
                                taskId: taskId,
                                plannedUtc: task.PlannedUtc,
                                actualUtc: _clock.UtcNow));
                        });
                    }
                    catch (Exception ex)
                    {
                        _log.Error("Cancel", "取消任务后保存规则解除状态失败", ex);
                        failures.Add($"规则已处理，但状态保存失败：{ex.Message}");
                    }
                }
            }
        }
        else
        {
            try
            {
                _store.Mutate(s =>
                {
                    var stored = s.Tasks.FirstOrDefault(t => t.TaskId == taskId);
                    if (stored is not null)
                        stored.ResultMessage = schedulerError is null
                            ? "用户取消了此定时任务，并选择保留当前防火墙规则状态。"
                            : "用户取消了此定时任务；逻辑取消已生效，但系统计划任务记录删除失败。";
                });
            }
            catch (Exception ex)
            {
                _log.Warn("Cancel", $"更新取消结果说明失败：{ex.Message}");
            }
        }

        var success = failures.Count == 0;
        var summary = success
            ? "定时任务已取消，后续不会被系统计划任务执行。"
            : "定时任务已取消，但部分附带操作失败：" + string.Join("；", failures);
        if (unblockRemoved > 0 || unblockMissing > 0)
            summary += $" 已解除 {unblockRemoved} 条规则，{unblockMissing} 条操作时已不存在。";
        if (warnings.Count > 0)
            summary += " " + string.Join("；", warnings);
        if (schedulerError is not null || failures.Count > 0)
            SafeAppendEvent(NewEvent(
                "取消定时任务（完成）",
                new ValidatedTarget(task.TargetKind, task.Target, task.DisplayTarget),
                success ? OperationOutcome.Warning : OperationOutcome.Failure,
                summary,
                null, source, correlationId, taskId: taskId, actualUtc: _clock.UtcNow));

        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = success,
            Outcome = success
                ? (schedulerError is not null ? OperationOutcome.Warning : OperationOutcome.Success)
                : OperationOutcome.Failure,
            Message = summary,
            TaskId = taskId
        };
    }

    private static string BuildCancelResultMessage(bool schedulerDeleted, int removed, int missing, int failed)
    {
        var parts = new List<string>
        {
            schedulerDeleted ? "任务已取消。" : "任务已逻辑取消，但系统计划任务记录删除失败。"
        };
        if (removed > 0 || missing > 0 || failed > 0)
            parts.Add($"已解除 {removed} 条规则，{missing} 条此前已不存在，{failed} 条解除失败。");
        return string.Join(" ", parts);
    }

    private RemovalBatchResult RemoveRulesCore(IReadOnlyList<ManagedRuleRecord> records)
    {
        var result = new RemovalBatchResult();
        if (records.Count == 0) return result;

        FirewallInspectionBatch batch;
        try
        {
            batch = _firewall.InspectRules(records);
        }
        catch (Exception ex)
        {
            result.Failed.AddRange(records.Select(r => $"{r.FirewallRuleName}：无法读取规则状态：{ex.Message}"));
            return result;
        }

        foreach (var record in records)
        {
            if (record.Status != ManagedRuleStatus.Active)
            {
                result.Missing.Add(record);
                continue;
            }
            batch.Inspections.TryGetValue(record.RuleId, out var inspection);
            if (inspection is null || inspection.State == RuleInspectionState.Unknown)
            {
                result.Failed.Add($"{record.FirewallRuleName}：{inspection?.Detail ?? "无法读取规则状态"}");
                continue;
            }
            if (inspection.State == RuleInspectionState.Missing)
            {
                result.Missing.Add(record);
                continue;
            }
            if (!inspection.IdentityMatches)
            {
                result.Failed.Add($"{record.FirewallRuleName}：同名规则不是本工具登记的身份，拒绝删除");
                continue;
            }
            try
            {
                _firewall.RemoveRule(record.FirewallRuleName, record.RuleId);
                result.Removed.Add(record);
            }
            catch (Exception ex)
            {
                result.Failed.Add($"{record.FirewallRuleName}：{ex.Message}");
            }
        }
        return result;
    }

    private sealed class RemovalBatchResult
    {
        public List<ManagedRuleRecord> Removed { get; } = new();
        public List<ManagedRuleRecord> Missing { get; } = new();
        public List<string> Failed { get; } = new();
    }
}
