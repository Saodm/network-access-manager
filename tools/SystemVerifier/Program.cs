using System.Diagnostics;
using System.Text;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Firewall;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Network;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Scheduling;
using NetworkAccessManager.Core.Security;

var output = new StringBuilder();
var passed = false;
AppPaths? paths = null;
StateRepository? store = null;
ComFirewallManager? firewall = null;
TaskSchedulerRegistrar? scheduler = null;
var dataDirectory = args
    .FirstOrDefault(a => a.StartsWith("--data-dir=", StringComparison.OrdinalIgnoreCase))?
    ["--data-dir=".Length..] ?? Path.Combine(Environment.CurrentDirectory, "artifacts", "system-verifier");
dataDirectory = Path.GetFullPath(dataDirectory);
var appExecutable = args
    .FirstOrDefault(a => a.StartsWith("--app-exe=", StringComparison.OrdinalIgnoreCase))?
    ["--app-exe=".Length..] ?? Path.Combine(Environment.CurrentDirectory, "src", "NetworkAccessManager.App", "bin", "Debug", "net10.0-windows", "NetworkAccessManager.exe");
appExecutable = Path.GetFullPath(appExecutable);
Directory.CreateDirectory(dataDirectory);

void W(string line)
{
    Console.WriteLine(line);
    output.AppendLine(line);
}

if (args.Contains("--network-inspect", StringComparer.OrdinalIgnoreCase))
{
    try
    {
        var controller = new WindowsEthernetController();
        W($"NETWORK_IS_ADMIN={WindowsPrivilege.IsAdministrator()}");
        foreach (var adapter in controller.Inspect())
            W($"ADAPTER id={adapter.Id} name={adapter.Name} desc={adapter.Description} status={adapter.StatusText} admin={adapter.AdminEnabled} mac={adapter.MacAddress}");
        W("NETWORK_INSPECT=PASS");
        passed = true;
    }
    catch (Exception ex)
    {
        W("NETWORK_INSPECT_FAIL " + ex);
        passed = false;
    }
    try
    {
        File.WriteAllText(Path.Combine(dataDirectory, "verifier-output.txt"), output.ToString(), new UTF8Encoding(false));
    }
    catch { }
    return passed ? 0 : 1;
}

try
{
    W($"DATA_DIR={dataDirectory}");
    W($"IS_ADMIN={WindowsPrivilege.IsAdministrator()} USER={WindowsPrivilege.CurrentUserName()} SID={WindowsPrivilege.CurrentUserSid()}");
    W($"PROCESS={Environment.ProcessPath}");
    W($"TIME={DateTimeOffset.Now:O}");

    paths = new AppPaths(dataDirectory);
    paths.EnsureDirectories();
    store = new StateRepository(paths);
    firewall = new ComFirewallManager();
    var availability = firewall.GetAvailability();
    W($"FIREWALL_AVAILABLE={availability.IsAvailable} PROFILE_PROTECTED={availability.IsCurrentProfileProtected} CAN_READ={availability.CanReadRules} ACCESS_LIMITED={availability.IsAccessLimited}");
    W($"FIREWALL_STATUS={availability.StatusText} ERROR={availability.Error}");
    if (!firewall.IsElevated)
        throw new InvalidOperationException("The verifier is not running with the privileges required by NetworkControlService. Launch it through an elevated SYSTEM scheduled task.");

    scheduler = new TaskSchedulerRegistrar(paths, appExecutable);
    var service = new NetworkControlService(store, firewall, scheduler, SystemClock.Instance,
        NullAppLog.Instance, Environment.ProcessPath);
    W($"APP_EXECUTABLE={appExecutable} EXISTS={File.Exists(appExecutable)}");

    var notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
    const string networkTarget = "203.0.113.0/24";
    if (!File.Exists(notepad))
        throw new FileNotFoundException("notepad.exe was not found for the harmless program-rule test.", notepad);
    W($"TEST_PROGRAM={notepad}");
    W($"TEST_NETWORK={networkTarget}");

    var blockProgram = new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.BlockProgram,
        TargetKind = RuleTargetKind.Program,
        Target = notepad,
        Directions = BlockDirections.Outbound
    };
    var programResult = await service.RunActionAsync(blockProgram, "SystemVerifier", "system-verifier");
    W($"BLOCK_PROGRAM success={programResult.Success} outcome={programResult.Outcome} message={programResult.Message}");
    W($"BLOCK_PROGRAM_RULE_IDS={string.Join(',', programResult.RuleIds)}");
    if (!programResult.Success) throw new InvalidOperationException("Program block failed; no further mutation will be attempted.");

    var blockNetwork = new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.BlockNetworkAddress,
        TargetKind = RuleTargetKind.NetworkAddress,
        Target = networkTarget,
        Directions = BlockDirections.Outbound
    };
    var networkResult = await service.RunActionAsync(blockNetwork, "SystemVerifier", "system-verifier");
    W($"BLOCK_NETWORK success={networkResult.Success} outcome={networkResult.Outcome} message={networkResult.Message}");
    W($"BLOCK_NETWORK_RULE_IDS={string.Join(',', networkResult.RuleIds)}");
    if (!networkResult.Success) throw new InvalidOperationException("Network block failed.");

    var state = store.ReadState().State;
    var active = state.Rules.Where(r => r.Status == ManagedRuleStatus.Active).ToList();
    W($"STATE_ACTIVE_RULES={active.Count}");
    foreach (var rule in active)
        W($"RULE record={rule.RuleId} name={rule.FirewallRuleName} kind={rule.TargetKind} target={rule.Target} direction={rule.Direction} verified={rule.VerifiedUtc:O}");

    var inspection = firewall.InspectRules(active);
    foreach (var rule in active)
    {
        if (!inspection.Inspections.TryGetValue(rule.RuleId, out var item))
        {
            W($"INSPECT_MISSING rule={rule.RuleId}");
            continue;
        }
        W($"INSPECT rule={rule.RuleId} state={item.State} exists={item.Exists} enabled={item.IsEnabled} identity={item.IdentityMatches} direction={item.Direction} application={item.ApplicationName} remote={item.RemoteAddresses} detail={item.Detail}");
    }

    var orphansWhileActive = firewall.FindManagedOrphanRuleNames(active.Select(r => r.FirewallRuleName).ToHashSet(StringComparer.OrdinalIgnoreCase));
    W($"ORPHANS_WHILE_ACTIVE={string.Join(',', orphansWhileActive)}");

    foreach (var rule in active)
    {
        W($"NETSH_BEGIN {rule.FirewallRuleName}");
        W(RunNetsh(rule.FirewallRuleName));
        W($"NETSH_END {rule.FirewallRuleName}");
    }

    var unblockProgram = new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.UnblockTarget,
        TargetKind = RuleTargetKind.Program,
        Target = notepad
    };
    var unblockProgramResult = await service.RunActionAsync(unblockProgram, "SystemVerifier", "system-verifier");
    W($"UNBLOCK_PROGRAM success={unblockProgramResult.Success} outcome={unblockProgramResult.Outcome} message={unblockProgramResult.Message}");
    if (!unblockProgramResult.Success) throw new InvalidOperationException("Program unblock failed.");

    var unblockNetwork = new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.UnblockTarget,
        TargetKind = RuleTargetKind.NetworkAddress,
        Target = networkTarget
    };
    var unblockNetworkResult = await service.RunActionAsync(unblockNetwork, "SystemVerifier", "system-verifier");
    W($"UNBLOCK_NETWORK success={unblockNetworkResult.Success} outcome={unblockNetworkResult.Outcome} message={unblockNetworkResult.Message}");
    if (!unblockNetworkResult.Success) throw new InvalidOperationException("Network unblock failed.");

    var after = store.ReadState().State;
    var stillActive = after.Rules.Where(r => r.Status == ManagedRuleStatus.Active).ToList();
    W($"STATE_ACTIVE_AFTER_UNBLOCK={stillActive.Count}");
    var orphansAfter = firewall.FindManagedOrphanRuleNames(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    W($"ORPHANS_AFTER_UNBLOCK={string.Join(',', orphansAfter)}");
    var historyCount = after.Events.Count;
    W($"HISTORY_EVENTS={historyCount}");
    foreach (var item in after.Events.TakeLast(12))
        W($"EVENT {item.TimestampUtc:O} outcome={item.Outcome} op={item.Operation} message={item.Message}");

    var schedulerPassed = false;
    var scheduledTaskName = string.Empty;
    try
    {
        var taskId = Guid.NewGuid().ToString("N");
        scheduledTaskName = TaskNamePolicy.ForTask(taskId);
        W($"SCHEDULER_CREATE name={scheduledTaskName} action={appExecutable} --execute-task={taskId}");
        await scheduler.RegisterAsync(scheduledTaskName, $"--execute-task={taskId}",
            DateTimeOffset.UtcNow.AddMinutes(10), "Network Access Manager integration verification");
        var exists = await scheduler.ExistsAsync(scheduledTaskName);
        var query = await scheduler.QueryAsync(scheduledTaskName);
        W($"SCHEDULER_REGISTERED exists={exists} accessible={query.Accessible} detail={query.Detail} error={query.Error}");
        await scheduler.DeleteAsync(scheduledTaskName);
        var existsAfter = await scheduler.ExistsAsync(scheduledTaskName);
        W($"SCHEDULER_AFTER_DELETE exists={existsAfter}");
        schedulerPassed = exists && existsAfter == false;
    }
    catch (Exception schedulerException)
    {
        W($"SCHEDULER_EXCEPTION {schedulerException}");
        try
        {
            if (TaskNamePolicy.IsValid(scheduledTaskName))
                await scheduler.DeleteAsync(scheduledTaskName);
        }
        catch (Exception cleanupException)
        {
            W($"SCHEDULER_CLEANUP_EXCEPTION {cleanupException.Message}");
        }
    }
    W($"SCHEDULER_RESULT={(schedulerPassed ? "PASS" : "FAIL")}");

    var workflowsPassed = true;
    void Workflow(string name, bool ok, string detail)
    {
        workflowsPassed &= ok;
        W($"WORKFLOW {name} {(ok ? "PASS" : "FAIL")} {detail}");
    }

    // 1. Delayed block: register a real OS task, then run the same executor the
    // task helper calls. This is the scheduled-execution code path, without
    // waiting for the real clock.
    var delayedBlock = await service.RunActionAsync(new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.ScheduleDelayedBlock,
        TargetKind = RuleTargetKind.Program,
        Target = notepad,
        Directions = BlockDirections.Outbound,
        DelayMinutes = 1
    }, "SystemVerifier", "system-verifier");
    var delayedBlockState = store.ReadState().State;
    var delayedBlockTask = delayedBlock.TaskId is null
        ? null
        : delayedBlockState.Tasks.FirstOrDefault(t => t.TaskId == delayedBlock.TaskId);
    var delayedBlockOs = delayedBlock.TaskName is not null && await scheduler.ExistsAsync(delayedBlock.TaskName);
    var delayedBlockExec = delayedBlock.TaskId is null
        ? new ScheduledExecutionResult { Success = false, Message = "no task id" }
        : await service.ExecuteScheduledTaskAsync(delayedBlock.TaskId);
    var delayedBlockAfter = store.ReadState().State;
    var delayedBlockTaskAfter = delayedBlock.TaskId is null
        ? null
        : delayedBlockAfter.Tasks.FirstOrDefault(t => t.TaskId == delayedBlock.TaskId);
    var delayedBlockRules = delayedBlockAfter.Rules.Where(r => r.Status == ManagedRuleStatus.Active && string.Equals(r.Target, notepad, StringComparison.OrdinalIgnoreCase)).ToList();
    var delayedBlockInspection = delayedBlockRules.Count == 0
        ? new FirewallInspectionBatch()
        : firewall.InspectRules(delayedBlockRules);
    var delayedBlockOsAfter = delayedBlock.TaskName is null || await scheduler.ExistsAsync(delayedBlock.TaskName);
    Workflow("DelayedBlock",
        delayedBlock.Success &&
        delayedBlockTask?.Status == ScheduledTaskStatus.Pending &&
        delayedBlockOs &&
        delayedBlockExec.Success &&
        delayedBlockTaskAfter?.Status == ScheduledTaskStatus.Succeeded &&
        delayedBlockRules.Count == 1 &&
        delayedBlockInspection.Inspections.Values.All(i => i.State == RuleInspectionState.Verified) &&
        delayedBlockOsAfter == false,
        $"schedule={delayedBlock.Success} pending={delayedBlockTask?.Status} os={delayedBlockOs} exec={delayedBlockExec.Success} final={delayedBlockTaskAfter?.Status} rules={delayedBlockRules.Count} osAfter={delayedBlockOsAfter} message={delayedBlock.Message}; execMessage={delayedBlockExec.Message}");
    if (delayedBlockRules.Count > 0)
        await service.RunActionAsync(new ElevatedAction { ActionId = Guid.NewGuid().ToString("N"), Kind = ElevatedActionKind.UnblockTarget, TargetKind = RuleTargetKind.Program, Target = notepad }, "SystemVerifier", "system-verifier");

    // 2. Delayed unblock: first create a permanent block, then schedule and
    // execute delayed removal against the real firewall.
    var delayedUnblockBlock = await service.RunActionAsync(new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.BlockProgram,
        TargetKind = RuleTargetKind.Program,
        Target = notepad,
        Directions = BlockDirections.Outbound
    }, "SystemVerifier", "system-verifier");
    var delayedUnblockSchedule = await service.RunActionAsync(new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.ScheduleDelayedUnblock,
        TargetKind = RuleTargetKind.Program,
        Target = notepad,
        Directions = BlockDirections.Outbound,
        DelayMinutes = 1
    }, "SystemVerifier", "system-verifier");
    var delayedUnblockOs = delayedUnblockSchedule.TaskName is not null && await scheduler.ExistsAsync(delayedUnblockSchedule.TaskName);
    var delayedUnblockExec = delayedUnblockSchedule.TaskId is null
        ? new ScheduledExecutionResult { Success = false, Message = "no task id" }
        : await service.ExecuteScheduledTaskAsync(delayedUnblockSchedule.TaskId);
    var delayedUnblockAfter = store.ReadState().State;
    var delayedUnblockTaskAfter = delayedUnblockSchedule.TaskId is null
        ? null
        : delayedUnblockAfter.Tasks.FirstOrDefault(t => t.TaskId == delayedUnblockSchedule.TaskId);
    var delayedUnblockActive = delayedUnblockAfter.Rules.Count(r => r.Status == ManagedRuleStatus.Active);
    var delayedUnblockOsAfter = delayedUnblockSchedule.TaskName is null || await scheduler.ExistsAsync(delayedUnblockSchedule.TaskName);
    Workflow("DelayedUnblock",
        delayedUnblockBlock.Success &&
        delayedUnblockSchedule.Success &&
        delayedUnblockOs &&
        delayedUnblockExec.Success &&
        delayedUnblockTaskAfter?.Status == ScheduledTaskStatus.Succeeded &&
        delayedUnblockActive == 0 &&
        delayedUnblockOsAfter == false,
        $"block={delayedUnblockBlock.Success} schedule={delayedUnblockSchedule.Success} os={delayedUnblockOs} exec={delayedUnblockExec.Success} final={delayedUnblockTaskAfter?.Status} active={delayedUnblockActive} osAfter={delayedUnblockOsAfter} message={delayedUnblockExec.Message}");

    // 3. Timed block: immediate rule plus an auto-unblock task. Execute the
    // task through the same helper code path and confirm automatic restoration.
    var timedBlock = await service.RunActionAsync(new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.ScheduleTimedBlock,
        TargetKind = RuleTargetKind.Program,
        Target = notepad,
        Directions = BlockDirections.Outbound,
        DelayMinutes = 1
    }, "SystemVerifier", "system-verifier");
    var timedBlockState = store.ReadState().State;
    var timedBlockTask = timedBlock.TaskId is null ? null : timedBlockState.Tasks.FirstOrDefault(t => t.TaskId == timedBlock.TaskId);
    var timedBlockRules = timedBlockState.Rules.Where(r => r.Status == ManagedRuleStatus.Active && string.Equals(r.Target, notepad, StringComparison.OrdinalIgnoreCase)).ToList();
    var timedBlockInspection = timedBlockRules.Count == 0 ? new FirewallInspectionBatch() : firewall.InspectRules(timedBlockRules);
    var timedBlockOs = timedBlock.TaskName is not null && await scheduler.ExistsAsync(timedBlock.TaskName);
    var timedBlockExec = timedBlock.TaskId is null
        ? new ScheduledExecutionResult { Success = false, Message = "no task id" }
        : await service.ExecuteScheduledTaskAsync(timedBlock.TaskId);
    var timedBlockAfter = store.ReadState().State;
    var timedBlockTaskAfter = timedBlock.TaskId is null ? null : timedBlockAfter.Tasks.FirstOrDefault(t => t.TaskId == timedBlock.TaskId);
    var timedBlockActiveAfter = timedBlockAfter.Rules.Count(r => r.Status == ManagedRuleStatus.Active);
    var timedBlockOsAfter = timedBlock.TaskName is null || await scheduler.ExistsAsync(timedBlock.TaskName);
    Workflow("TimedBlock",
        timedBlock.Success &&
        timedBlockTask?.Status == ScheduledTaskStatus.Pending &&
        timedBlockRules.Count == 1 &&
        timedBlockInspection.Inspections.Values.All(i => i.State == RuleInspectionState.Verified) &&
        timedBlockOs &&
        timedBlockExec.Success &&
        timedBlockTaskAfter?.Status == ScheduledTaskStatus.Succeeded &&
        timedBlockActiveAfter == 0 &&
        timedBlockOsAfter == false,
        $"schedule={timedBlock.Success} pending={timedBlockTask?.Status} rules={timedBlockRules.Count} os={timedBlockOs} exec={timedBlockExec.Success} final={timedBlockTaskAfter?.Status} activeAfter={timedBlockActiveAfter} osAfter={timedBlockOsAfter} message={timedBlockExec.Message}");
    if (timedBlockActiveAfter > 0)
        await service.RunActionAsync(new ElevatedAction { ActionId = Guid.NewGuid().ToString("N"), Kind = ElevatedActionKind.UnblockTarget, TargetKind = RuleTargetKind.Program, Target = notepad }, "SystemVerifier", "system-verifier");

    // 4. Cancel a pending delayed block. The logical cancellation must be
    // persisted and the OS task must be removed.
    var cancelSchedule = await service.RunActionAsync(new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.ScheduleDelayedBlock,
        TargetKind = RuleTargetKind.Program,
        Target = notepad,
        Directions = BlockDirections.Inbound,
        DelayMinutes = 1
    }, "SystemVerifier", "system-verifier");
    var cancelOs = cancelSchedule.TaskName is not null && await scheduler.ExistsAsync(cancelSchedule.TaskName);
    var cancelResult = cancelSchedule.TaskId is null
        ? new ElevatedActionResult { Success = false, Message = "no task id" }
        : await service.RunActionAsync(new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.CancelScheduledTask,
            TaskId = cancelSchedule.TaskId,
            UnblockRulesOnCancel = false
        }, "SystemVerifier", "system-verifier");
    var cancelState = store.ReadState().State;
    var cancelTaskAfter = cancelSchedule.TaskId is null ? null : cancelState.Tasks.FirstOrDefault(t => t.TaskId == cancelSchedule.TaskId);
    var cancelOsAfter = cancelSchedule.TaskName is null || await scheduler.ExistsAsync(cancelSchedule.TaskName);
    Workflow("CancelDelayedBlock",
        cancelSchedule.Success && cancelOs && cancelResult.Success &&
        cancelTaskAfter?.Status == ScheduledTaskStatus.Cancelled && cancelOsAfter == false,
        $"schedule={cancelSchedule.Success} os={cancelOs} cancel={cancelResult.Success} final={cancelTaskAfter?.Status} osAfter={cancelOsAfter} message={cancelResult.Message}");

    // 5. Cancel a timed block with UnblockRulesOnCancel=true. This must remove
    // the already-created rule as well as the pending restoration task.
    var cancelTimed = await service.RunActionAsync(new ElevatedAction
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = ElevatedActionKind.ScheduleTimedBlock,
        TargetKind = RuleTargetKind.Program,
        Target = notepad,
        Directions = BlockDirections.Inbound,
        DelayMinutes = 1
    }, "SystemVerifier", "system-verifier");
    var cancelTimedRulesBefore = store.ReadState().State.Rules.Count(r => r.Status == ManagedRuleStatus.Active);
    var cancelTimedOs = cancelTimed.TaskName is not null && await scheduler.ExistsAsync(cancelTimed.TaskName);
    var cancelTimedResult = cancelTimed.TaskId is null
        ? new ElevatedActionResult { Success = false, Message = "no task id" }
        : await service.RunActionAsync(new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.CancelScheduledTask,
            TaskId = cancelTimed.TaskId,
            UnblockRulesOnCancel = true
        }, "SystemVerifier", "system-verifier");
    var cancelTimedState = store.ReadState().State;
    var cancelTimedTaskAfter = cancelTimed.TaskId is null ? null : cancelTimedState.Tasks.FirstOrDefault(t => t.TaskId == cancelTimed.TaskId);
    var cancelTimedActiveAfter = cancelTimedState.Rules.Count(r => r.Status == ManagedRuleStatus.Active);
    var cancelTimedOsAfter = cancelTimed.TaskName is null || await scheduler.ExistsAsync(cancelTimed.TaskName);
    Workflow("CancelTimedBlockWithUnblock",
        cancelTimed.Success && cancelTimedRulesBefore == 1 && cancelTimedOs && cancelTimedResult.Success &&
        cancelTimedTaskAfter?.Status == ScheduledTaskStatus.Cancelled &&
        cancelTimedActiveAfter == 0 && cancelTimedOsAfter == false,
        $"schedule={cancelTimed.Success} rulesBefore={cancelTimedRulesBefore} os={cancelTimedOs} cancel={cancelTimedResult.Success} final={cancelTimedTaskAfter?.Status} activeAfter={cancelTimedActiveAfter} osAfter={cancelTimedOsAfter} message={cancelTimedResult.Message}");

    var workflowsState = store.ReadState().State;
    var workflowsPending = workflowsState.Tasks.Count(t => t.Status is ScheduledTaskStatus.Pending or ScheduledTaskStatus.Running);
    var workflowsActiveRules = workflowsState.Rules.Count(r => r.Status == ManagedRuleStatus.Active);
    var workflowsOrphans = firewall.FindManagedOrphanRuleNames(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    W($"WORKFLOW_FINAL pending={workflowsPending} activeRules={workflowsActiveRules} orphans={string.Join(',', workflowsOrphans)}");
    if (workflowsPending != 0 || workflowsActiveRules != 0 || workflowsOrphans.Count != 0)
        workflowsPassed = false;

    passed = active.Count == 2 &&
             inspection.Inspections.Count == 2 &&
             inspection.Inspections.Values.All(i => i.State == RuleInspectionState.Verified && i.IdentityMatches) &&
             stillActive.Count == 0 &&
             orphansAfter.Count == 0 &&
             schedulerPassed &&
             workflowsPassed;
    W($"FIREWALL_RESULT={(active.Count == 2 && stillActive.Count == 0 && orphansAfter.Count == 0 ? "PASS" : "FAIL")}");
    W($"WORKFLOWS_RESULT={(workflowsPassed ? "PASS" : "FAIL")}");
    W($"RESULT={(passed ? "PASS" : "FAIL")}");
}
catch (Exception ex)
{
    W($"EXCEPTION {ex}");
    W("RESULT=FAIL");
}
finally
{
    try
    {
        if (scheduler is not null && store is not null)
        {
            var pendingTasks = store.ReadState().State.Tasks
                .Where(t => t.Status is ScheduledTaskStatus.Pending or ScheduledTaskStatus.Running)
                .ToList();
            foreach (var task in pendingTasks)
            {
                W($"CLEANUP_TASK_BEGIN task={task.TaskId} name={task.ScheduledTaskName}");
                try
                {
                    await scheduler.DeleteAsync(task.ScheduledTaskName);
                }
                catch (Exception taskCleanupEx)
                {
                    W($"CLEANUP_TASK_DELETE_FAILED task={task.TaskId} error={taskCleanupEx.Message}");
                }
                try
                {
                    store.Mutate(state =>
                    {
                        var stored = state.Tasks.FirstOrDefault(t => t.TaskId == task.TaskId);
                        if (stored is not null && stored.Status == ScheduledTaskStatus.Pending)
                        {
                            stored.Status = ScheduledTaskStatus.Cancelled;
                            stored.CompletedUtc = DateTimeOffset.UtcNow;
                            stored.ResultMessage = "SystemVerifier safety cleanup";
                        }
                    });
                }
                catch (Exception taskStateEx)
                {
                    W($"CLEANUP_TASK_STATE_FAILED task={task.TaskId} error={taskStateEx.Message}");
                }
            }
        }
        if (firewall is not null && store is not null)
        {
            var remaining = store.ReadState().State.Rules
                .Where(r => r.Status == ManagedRuleStatus.Active)
                .ToList();
            foreach (var rule in remaining)
            {
                W($"CLEANUP_BEGIN record={rule.RuleId} name={rule.FirewallRuleName} target={rule.Target}");
                try
                {
                    firewall.RemoveRule(rule.FirewallRuleName, rule.RuleId);
                    store.Mutate(state =>
                    {
                        var record = state.Rules.FirstOrDefault(r => string.Equals(r.RuleId, rule.RuleId, StringComparison.OrdinalIgnoreCase));
                        if (record is not null)
                        {
                            record.Status = ManagedRuleStatus.RemovedByUser;
                            record.Note = "SystemVerifier safety cleanup";
                        }
                        state.Events.Add(new OperationHistoryEvent
                        {
                            Operation = "VerifierCleanup",
                            TargetKind = rule.TargetKind,
                            Target = rule.Target,
                            RuleId = rule.RuleId,
                            ActualUtc = DateTimeOffset.UtcNow,
                            Outcome = OperationOutcome.Warning,
                            Message = "系统验证器的安全清理已删除测试规则。",
                            Source = "SystemVerifier"
                        });
                    });
                    W("CLEANUP_REMOVED");
                }
                catch (Exception cleanupEx)
                {
                    W($"CLEANUP_FAILED record={rule.RuleId} error={cleanupEx.Message}");
                }
            }
            var orphans = firewall.FindManagedOrphanRuleNames(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            W($"CLEANUP_ORPHANS={string.Join(',', orphans)}");
        }
    }
    catch (Exception cleanupEx)
    {
        W("CLEANUP_EXCEPTION " + cleanupEx);
    }

    try
    {
        output.AppendLine($"COMPLETED={DateTimeOffset.Now:O}");
        File.WriteAllText(Path.Combine(dataDirectory, "verifier-output.txt"), output.ToString(), new UTF8Encoding(false));
    }
    catch (Exception ex)
    {
        Console.WriteLine("OUTPUT_WRITE_FAILED " + ex.Message);
    }
}

return passed ? 0 : 1;

static string RunNetsh(string ruleName)
{
    try
    {
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("advfirewall");
        psi.ArgumentList.Add("firewall");
        psi.ArgumentList.Add("show");
        psi.ArgumentList.Add("rule");
        psi.ArgumentList.Add("name=" + ruleName);
        using var process = Process.Start(psi);
        if (process is null) return "NETSH_START_FAILED";
        var text = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(15000))
        {
            try { process.Kill(true); } catch { }
            return "NETSH_TIMEOUT";
        }
        if (!string.IsNullOrWhiteSpace(error)) text += Environment.NewLine + "STDERR=" + error;
        return text.TrimEnd();
    }
    catch (Exception ex)
    {
        return "NETSH_EXCEPTION " + ex.Message;
    }
}
