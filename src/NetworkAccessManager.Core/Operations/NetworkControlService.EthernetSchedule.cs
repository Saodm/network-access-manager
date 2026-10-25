using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Network;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.Core.Operations;

public sealed partial class NetworkControlService
{
    /// <summary>
    /// Registers a one-shot Windows task that disables all currently enabled
    /// physical Ethernet adapters after the requested delay. The adapter list
    /// is re-read at execution time; no stale adapter state is trusted.
    /// </summary>
    private async Task<ElevatedActionResult> ScheduleDelayedEthernetDisableAsync(
        ElevatedAction action,
        string source,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        var delay = action.DelayMinutes!.Value;
        StateReadResultGuard(out var state, out var readError);
        if (readError is not null) return Failure(action, readError, source, correlationId);

        if (state.Ethernet is { IsDisabledByTool: true } ||
            state.Ethernet?.DisabledAdapters.Count > 0)
        {
            return Failure(action, "以太网当前已经由本工具禁用。请先恢复网络，再安排延迟禁网。", source, correlationId);
        }

        if (state.Tasks.Any(t =>
                t.Mode == ScheduledMode.DelayedEthernetDisable &&
                t.Status is ScheduledTaskStatus.Pending or ScheduledTaskStatus.Running))
        {
            return Failure(action, "已经有一个待执行或正在执行的延迟禁网任务。请先在“任务与历史”中取消或等待它完成。", source, correlationId);
        }

        IReadOnlyList<EthernetAdapterInfo> adapters;
        try
        {
            adapters = _ethernet.Inspect();
        }
        catch (Exception ex)
        {
            return Failure(action, "读取物理以太网适配器失败，未创建任务：" + ex.Message, source, correlationId, ex.ToString());
        }

        if (!adapters.Any(a => a.AdminEnabled == true))
        {
            return Failure(action, "没有发现处于启用状态的物理以太网适配器，未创建延迟禁网任务。", source, correlationId);
        }

        var now = _clock.UtcNow;
        var plannedUtc = now.AddMinutes(delay);
        var taskId = Guid.NewGuid().ToString("N");
        var taskName = Scheduling.TaskNamePolicy.ForTask(taskId);
        var target = new ValidatedTarget(
            RuleTargetKind.Ethernet,
            "所有物理以太网适配器",
            "所有物理以太网适配器");
        var record = new ScheduledTaskRecord
        {
            TaskId = taskId,
            Mode = ScheduledMode.DelayedEthernetDisable,
            ExecutionAction = ScheduledExecutionAction.EthernetDisable,
            Status = ScheduledTaskStatus.Pending,
            TargetKind = RuleTargetKind.Ethernet,
            Target = target.Value,
            DisplayTarget = target.Display,
            Directions = BlockDirections.None,
            PlannedRules = new List<PlannedRule>(),
            ScheduledTaskName = taskName,
            CreatedUtc = now,
            PlannedUtc = plannedUtc,
            CreatedBy = WindowsPrivilege.CurrentUserName(),
            CorrelationId = correlationId
        };

        try
        {
            await _scheduler.RegisterAsync(
                taskName,
                $"--execute-task={taskId}",
                plannedUtc,
                BuildScheduleDescription("延迟禁网", target),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Error("Schedule", "注册延迟禁网计划任务失败", ex);
            TryLogFailureEvent("延迟禁网", target, source, correlationId, ex.Message, taskId);
            return Failure(action, $"无法注册 Windows 计划任务：{ex.Message}", source, correlationId, ex.ToString());
        }

        try
        {
            _store.Mutate(s =>
            {
                s.Tasks.Add(record);
                s.Events.Add(NewEvent(
                    "延迟禁网", target, OperationOutcome.Success,
                    $"已创建延迟禁网任务，计划于 {TimeDisplay.LocalDateTime(plannedUtc)} 禁用所有当前启用的物理以太网适配器。",
                    "到时不会自动恢复；可以从主界面或系统托盘恢复网络。",
                    source, correlationId, taskId: taskId, plannedUtc: plannedUtc));
            });
        }
        catch (Exception ex)
        {
            await TryDeleteTaskAsync(taskName).ConfigureAwait(false);
            _log.Error("Schedule", "延迟禁网任务状态保存失败", ex);
            return Failure(action, $"状态数据保存失败，计划任务已回滚：{ex.Message}", source, correlationId, ex.ToString());
        }

        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = true,
            Outcome = OperationOutcome.Success,
            Message = $"已创建延迟禁网任务。将在 {delay} 分钟后（{TimeDisplay.LocalDateTime(plannedUtc)}）禁用所有当前启用的物理以太网适配器。关闭程序后任务仍由 Windows 执行；到时不会自动恢复。若电脑休眠或关机，系统会在恢复并登录后尝试补执行，实际执行时间将如实记入历史。",
            TaskId = taskId,
            TaskName = taskName,
            PlannedUtc = plannedUtc
        };
    }

    private ScheduledExecutionResult ExecuteScheduledEthernetDisable(ScheduledTaskRecord task)
    {
        var target = new ValidatedTarget(
            RuleTargetKind.Ethernet,
            string.IsNullOrWhiteSpace(task.Target) ? "所有物理以太网适配器" : task.Target,
            string.IsNullOrWhiteSpace(task.DisplayTarget) ? "所有物理以太网适配器" : task.DisplayTarget);
        var result = ExecuteEthernetDisable(
            new ElevatedAction
            {
                ActionId = task.TaskId,
                Kind = ElevatedActionKind.DisableEthernet,
                TargetKind = RuleTargetKind.Ethernet,
                Directions = BlockDirections.None
            },
            "系统计划任务",
            task.CorrelationId);

        var status = result.Success ? ScheduledTaskStatus.Succeeded : ScheduledTaskStatus.Failed;
        CompleteTask(task.TaskId, status, result.Message, target: target);
        return new ScheduledExecutionResult
        {
            Success = result.Success,
            ExitCode = result.Success ? 0 : 2,
            Message = result.Message
        };
    }
}
