using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.Tests;

public sealed class NetworkControlServiceTests
{
    private static async Task<(TempWorkspace Workspace, FakeFirewallManager Firewall, FakeScheduler Scheduler, FakeClock Clock, NetworkControlService Service)>
        CreateAsync()
    {
        var workspace = new TempWorkspace();
        var firewall = new FakeFirewallManager();
        var scheduler = new FakeScheduler();
        var clock = new FakeClock();
        var service = TestServiceFactory.Create(workspace, firewall, scheduler, clock);
        await Task.CompletedTask;
        return (workspace, firewall, scheduler, clock, service);
    }

    private static ElevatedAction ScheduleAction(string kind, TempWorkspace workspace, int minutes = 10) => kind switch
    {
        "delayedBlock" => new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.ScheduleDelayedBlock,
            TargetKind = RuleTargetKind.Program,
            Target = workspace.DummyExePath,
            Directions = BlockDirections.Outbound,
            DelayMinutes = minutes
        },
        "delayedUnblock" => new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.ScheduleDelayedUnblock,
            TargetKind = RuleTargetKind.Program,
            Target = workspace.DummyExePath,
            Directions = BlockDirections.Outbound,
            DelayMinutes = minutes
        },
        "timedBlock" => new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.ScheduleTimedBlock,
            TargetKind = RuleTargetKind.Program,
            Target = workspace.DummyExePath,
            Directions = BlockDirections.Outbound,
            DelayMinutes = minutes
        },
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    [Fact]
    public async Task Immediate_block_creates_verified_rule_and_unblock_removes_it()
    {
        var (workspace, firewall, _, _, service) = await CreateAsync();
        using var _w = workspace;
        var action = TestServiceFactory.BlockProgram(workspace, BlockDirections.Both);

        var result = await service.RunActionAsync(action, "测试", "corr-block");
        Assert.True(result.Success, result.Message);
        Assert.Equal(2, result.RuleIds.Count);
        Assert.Equal(2, firewall.RuleNames.Count);

        var state = workspace.CreateStore().ReadState().State;
        Assert.Equal(2, state.Rules.Count);
        Assert.All(state.Rules, r => Assert.Equal(ManagedRuleStatus.Active, r.Status));
        Assert.Contains(state.Events, e => e.Operation == "立即禁止" && e.Outcome == OperationOutcome.Success);

        var unblock = new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.UnblockTarget,
            TargetKind = RuleTargetKind.Program,
            Target = workspace.DummyExePath
        };
        var unblockResult = await service.RunActionAsync(unblock, "测试", "corr-unblock");
        Assert.True(unblockResult.Success, unblockResult.Message);
        Assert.Empty(firewall.RuleNames);
        state = workspace.CreateStore().ReadState().State;
        Assert.All(state.Rules, r => Assert.Equal(ManagedRuleStatus.RemovedByUser, r.Status));
    }

    [Fact]
    public async Task Second_block_does_not_create_duplicate_rule()
    {
        var (workspace, _, _, _, service) = await CreateAsync();
        using var _w = workspace;
        var first = await service.RunActionAsync(TestServiceFactory.BlockProgram(workspace), "测试", "c1");
        var second = await service.RunActionAsync(TestServiceFactory.BlockProgram(workspace), "测试", "c2");
        Assert.True(first.Success);
        Assert.True(second.Success);
        Assert.Equal(OperationOutcome.Info, second.Outcome);
        var state = workspace.CreateStore().ReadState().State;
        Assert.Single(state.Rules);
    }

    [Fact]
    public async Task Firewall_unavailable_prevents_rule_creation()
    {
        var (workspace, firewall, _, _, service) = await CreateAsync();
        using var _w = workspace;
        firewall.AvailabilityError = "模拟防火墙服务不可用";
        var result = await service.RunActionAsync(TestServiceFactory.BlockProgram(workspace), "测试", "c-fail");
        Assert.False(result.Success);
        Assert.Empty(firewall.RuleNames);
        var state = workspace.CreateStore().ReadState().State;
        Assert.Empty(state.Rules);
        Assert.Contains(state.Events, e => e.Outcome == OperationOutcome.Failure);
    }

    [Fact]
    public async Task Firewall_creation_error_does_not_record_a_block()
    {
        var (workspace, firewall, _, _, service) = await CreateAsync();
        using var _w = workspace;
        firewall.CreateError = "模拟规则创建失败";
        var result = await service.RunActionAsync(TestServiceFactory.BlockProgram(workspace), "测试", "c-fail2");
        Assert.False(result.Success);
        var state = workspace.CreateStore().ReadState().State;
        Assert.Empty(state.Rules);
    }

    [Fact]
    public async Task Protected_system_binary_is_refused_by_service()
    {
        var (workspace, firewall, _, _, service) = await CreateAsync();
        using var _w = workspace;
        var action = new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.BlockProgram,
            TargetKind = RuleTargetKind.Program,
            Target = Path.Combine(Environment.SystemDirectory, "svchost.exe"),
            Directions = BlockDirections.Outbound
        };
        var result = await service.RunActionAsync(action, "测试", "c-protected");
        Assert.False(result.Success);
        Assert.Contains("关键", result.Message);
        Assert.Empty(firewall.RuleNames);
    }

    [Fact]
    public async Task Timed_block_auto_unblocks_at_execution()
    {
        var (workspace, firewall, scheduler, clock, service) = await CreateAsync();
        using var _w = workspace;
        var schedule = ScheduleAction("timedBlock", workspace, 5);
        var result = await service.RunActionAsync(schedule, "测试", "timed");
        Assert.True(result.Success, result.Message);
        Assert.Single(firewall.RuleNames);
        Assert.NotNull(result.TaskId);
        Assert.Single(scheduler.Tasks);

        var state = workspace.CreateStore().ReadState().State;
        var task = Assert.Single(state.Tasks);
        Assert.Equal(ScheduledMode.TimedBlock, task.Mode);
        Assert.Equal(ScheduledTaskStatus.Pending, task.Status);
        Assert.Single(state.Rules);

        clock.Advance(TimeSpan.FromMinutes(6));
        var exec = await service.ExecuteScheduledTaskAsync(result.TaskId!);
        Assert.True(exec.Success, exec.Message);
        Assert.Empty(firewall.RuleNames);
        state = workspace.CreateStore().ReadState().State;
        Assert.Equal(ScheduledTaskStatus.Succeeded, state.Tasks.Single().Status);
        Assert.Equal(ManagedRuleStatus.RemovedByUser, state.Rules.Single().Status);
        Assert.NotNull(state.Tasks.Single().CompletedUtc);
        Assert.NotNull(state.Tasks.Single().StartedUtc);
    }

    [Fact]
    public async Task Cancel_timed_block_prevents_future_execution_and_can_unblock()
    {
        var (workspace, firewall, scheduler, clock, service) = await CreateAsync();
        using var _w = workspace;
        var schedule = ScheduleAction("timedBlock", workspace, 15);
        var created = await service.RunActionAsync(schedule, "测试", "cancel-setup");
        Assert.True(created.Success, created.Message);
        Assert.Single(firewall.RuleNames);

        var cancel = new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.CancelScheduledTask,
            TaskId = created.TaskId,
            UnblockRulesOnCancel = true
        };
        var canceled = await service.RunActionAsync(cancel, "测试", "cancel");
        Assert.True(canceled.Success, canceled.Message);
        Assert.Empty(firewall.RuleNames);
        Assert.Empty(scheduler.Tasks);
        var state = workspace.CreateStore().ReadState().State;
        Assert.Equal(ScheduledTaskStatus.Cancelled, state.Tasks.Single().Status);

        clock.Advance(TimeSpan.FromMinutes(30));
        var exec = await service.ExecuteScheduledTaskAsync(created.TaskId!);
        Assert.True(exec.Success);
        Assert.Empty(firewall.RuleNames);
        state = workspace.CreateStore().ReadState().State;
        Assert.Equal(ScheduledTaskStatus.Cancelled, state.Tasks.Single().Status);
    }

    [Fact]
    public async Task Cancel_with_scheduler_delete_failure_still_guarantees_logical_cancel()
    {
        var (workspace, firewall, scheduler, clock, service) = await CreateAsync();
        using var _w = workspace;
        var created = await service.RunActionAsync(ScheduleAction("timedBlock", workspace, 15), "测试", "sched-fail-setup");
        Assert.True(created.Success);
        scheduler.FailDeletion = true;
        var cancel = new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.CancelScheduledTask,
            TaskId = created.TaskId,
            UnblockRulesOnCancel = true
        };
        var result = await service.RunActionAsync(cancel, "测试", "sched-fail");
        Assert.True(result.Success, result.Message);
        Assert.Equal(OperationOutcome.Warning, result.Outcome);
        clock.Advance(TimeSpan.FromMinutes(30));
        await service.ExecuteScheduledTaskAsync(created.TaskId!);
        Assert.Empty(firewall.RuleNames);
        var state = workspace.CreateStore().ReadState().State;
        Assert.Equal(ScheduledTaskStatus.Cancelled, state.Tasks.Single().Status);
    }

    [Fact]
    public async Task Delayed_block_creates_rules_only_when_task_executes()
    {
        var (workspace, firewall, scheduler, clock, service) = await CreateAsync();
        using var _w = workspace;
        var result = await service.RunActionAsync(ScheduleAction("delayedBlock", workspace, 5), "测试", "delayed");
        Assert.True(result.Success, result.Message);
        Assert.Empty(firewall.RuleNames);
        Assert.Single(scheduler.Tasks);
        var initial = workspace.CreateStore().ReadState().State;
        Assert.Single(initial.Tasks);
        Assert.Empty(initial.Rules);

        clock.Advance(TimeSpan.FromMinutes(6));
        var exec = await service.ExecuteScheduledTaskAsync(result.TaskId!);
        Assert.True(exec.Success, exec.Message);
        Assert.Single(firewall.RuleNames);
        var state = workspace.CreateStore().ReadState().State;
        Assert.Single(state.Rules);
        Assert.Equal(ScheduledTaskStatus.Succeeded, state.Tasks.Single().Status);
        Assert.Empty(scheduler.Tasks);
    }

    [Fact]
    public async Task Delayed_unblock_keeps_block_until_execution()
    {
        var (workspace, firewall, scheduler, clock, service) = await CreateAsync();
        using var _w = workspace;
        var blocked = await service.RunActionAsync(TestServiceFactory.BlockProgram(workspace), "测试", "du-setup");
        Assert.True(blocked.Success);
        Assert.Single(firewall.RuleNames);

        var schedule = await service.RunActionAsync(ScheduleAction("delayedUnblock", workspace, 5), "测试", "du");
        Assert.True(schedule.Success, schedule.Message);
        Assert.Single(firewall.RuleNames);
        Assert.Single(scheduler.Tasks);

        clock.Advance(TimeSpan.FromMinutes(6));
        var exec = await service.ExecuteScheduledTaskAsync(schedule.TaskId!);
        Assert.True(exec.Success, exec.Message);
        Assert.Empty(firewall.RuleNames);
        var state = workspace.CreateStore().ReadState().State;
        Assert.Equal(ManagedRuleStatus.RemovedByUser, state.Rules.Single().Status);
        Assert.Equal(ScheduledTaskStatus.Succeeded, state.Tasks.Single().Status);
    }

    [Fact]
    public async Task External_deletion_before_auto_unblock_is_reported_as_failure()
    {
        var (workspace, firewall, _, clock, service) = await CreateAsync();
        using var _w = workspace;
        var result = await service.RunActionAsync(ScheduleAction("timedBlock", workspace, 5), "测试", "external-delete");
        Assert.True(result.Success);
        var record = workspace.CreateStore().ReadState().State.Rules.Single();
        firewall.SimulateExternalDelete(record.FirewallRuleName);
        clock.Advance(TimeSpan.FromMinutes(6));
        var exec = await service.ExecuteScheduledTaskAsync(result.TaskId!);
        Assert.False(exec.Success);
        var state = workspace.CreateStore().ReadState().State;
        Assert.Equal(ScheduledTaskStatus.Failed, state.Tasks.Single().Status);
        Assert.Equal(ManagedRuleStatus.RemovedExternally, state.Rules.Single().Status);
    }

    [Fact]
    public async Task External_modification_is_detected_by_refresh_inspection()
    {
        var (workspace, firewall, _, _, service) = await CreateAsync();
        using var _w = workspace;
        var result = await service.RunActionAsync(TestServiceFactory.BlockProgram(workspace), "测试", "external-mod");
        Assert.True(result.Success);
        var state = workspace.CreateStore().ReadState().State;
        var record = state.Rules.Single();
        firewall.SimulateExternalModify(record.FirewallRuleName);
        var batch = firewall.InspectRules(new[] { record });
        var inspection = batch.Inspections[record.RuleId];
        Assert.Equal(RuleInspectionState.Mismatched, inspection.State);
        Assert.True(inspection.IdentityMatches);
    }

    [Fact]
    public async Task Invalid_network_target_is_rejected_without_rule()
    {
        var (workspace, firewall, _, _, service) = await CreateAsync();
        using var _w = workspace;
        var action = new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.BlockNetworkAddress,
            TargetKind = RuleTargetKind.NetworkAddress,
            Target = "300.300.300.300/99",
            Directions = BlockDirections.Outbound
        };
        var result = await service.RunActionAsync(action, "测试", "bad-ip");
        Assert.False(result.Success);
        Assert.Empty(firewall.RuleNames);
        Assert.Contains("IPv4", result.Message + result.Detail);
    }

    [Fact]
    public async Task Restricted_profile_prevents_claiming_a_block()
    {
        var (workspace, firewall, _, _, service) = await CreateAsync();
        using var _w = workspace;
        firewall.ProfileDisabled = true;
        var result = await service.RunActionAsync(TestServiceFactory.BlockProgram(workspace), "测试", "profile");
        Assert.False(result.Success);
        Assert.Empty(firewall.RuleNames);
    }
}
