using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;

namespace NetworkAccessManager.Tests;

public sealed class EthernetControlTests
{
    private static ElevatedAction Action(ElevatedActionKind kind) => new()
    {
        ActionId = Guid.NewGuid().ToString("N"),
        Kind = kind
    };

    [Fact]
    public async Task Disable_records_adapter_and_restore_reenables_it()
    {
        using var workspace = new TempWorkspace();
        var firewall = new FakeFirewallManager();
        var scheduler = new FakeScheduler();
        var clock = new FakeClock();
        var ethernet = new FakeEthernetController();
        var service = TestServiceFactory.Create(workspace, firewall, scheduler, clock, ethernet);

        var disabled = await service.RunActionAsync(Action(ElevatedActionKind.DisableEthernet), "测试", "eth-disable");
        Assert.True(disabled.Success, disabled.Message);
        Assert.Equal(1, ethernet.DisableCalls);
        Assert.False(ethernet.Adapters[0].AdminEnabled);

        var state = workspace.CreateStore().ReadState().State;
        Assert.True(state.Ethernet.IsDisabledByTool);
        Assert.Single(state.Ethernet.DisabledAdapters);
        Assert.Contains(state.Events, e => e.Operation == "禁用以太网" && e.Outcome == OperationOutcome.Success);

        var restored = await service.RunActionAsync(Action(ElevatedActionKind.EnableEthernet), "测试", "eth-enable");
        Assert.True(restored.Success, restored.Message);
        Assert.Equal(1, ethernet.EnableCalls);
        Assert.True(ethernet.Adapters[0].AdminEnabled);

        state = workspace.CreateStore().ReadState().State;
        Assert.False(state.Ethernet.IsDisabledByTool);
        Assert.Empty(state.Ethernet.DisabledAdapters);
        Assert.Contains(state.Events, e => e.Operation == "恢复以太网" && e.Outcome == OperationOutcome.Success);
    }

    [Fact]
    public async Task Disable_with_no_enabled_adapter_is_an_informational_noop()
    {
        using var workspace = new TempWorkspace();
        var ethernet = new FakeEthernetController();
        ethernet.Adapters.Clear();
        var service = TestServiceFactory.Create(workspace, new FakeFirewallManager(), new FakeScheduler(), new FakeClock(), ethernet);

        var result = await service.RunActionAsync(Action(ElevatedActionKind.DisableEthernet), "测试", "eth-none");
        Assert.True(result.Success);
        Assert.Equal(OperationOutcome.Info, result.Outcome);
        Assert.Equal(0, ethernet.DisableCalls);

        var state = workspace.CreateStore().ReadState().State;
        Assert.False(state.Ethernet.IsDisabledByTool);
        Assert.Empty(state.Ethernet.DisabledAdapters);
    }

    [Fact]
    public async Task Failed_disable_does_not_leave_a_disabled_state_record()
    {
        using var workspace = new TempWorkspace();
        var ethernet = new FakeEthernetController { FailureMessage = "模拟适配器操作失败" };
        var service = TestServiceFactory.Create(workspace, new FakeFirewallManager(), new FakeScheduler(), new FakeClock(), ethernet);

        var result = await service.RunActionAsync(Action(ElevatedActionKind.DisableEthernet), "测试", "eth-fail");
        Assert.False(result.Success);
        Assert.NotEqual(OperationOutcome.Success, result.Outcome);
        Assert.True(ethernet.Adapters[0].AdminEnabled);

        var state = workspace.CreateStore().ReadState().State;
        Assert.False(state.Ethernet.IsDisabledByTool);
        Assert.Empty(state.Ethernet.DisabledAdapters);
        Assert.Contains(state.Events, e => e.Operation == "禁用以太网" && e.Outcome != OperationOutcome.Success);
    }

    [Fact]
    public async Task Restore_without_a_record_does_not_touch_adapters()
    {
        using var workspace = new TempWorkspace();
        var ethernet = new FakeEthernetController();
        var service = TestServiceFactory.Create(workspace, new FakeFirewallManager(), new FakeScheduler(), new FakeClock(), ethernet);

        var result = await service.RunActionAsync(Action(ElevatedActionKind.EnableEthernet), "测试", "eth-restore-none");
        Assert.True(result.Success);
        Assert.Equal(OperationOutcome.Info, result.Outcome);
        Assert.Equal(0, ethernet.EnableCalls);
        Assert.True(ethernet.Adapters[0].AdminEnabled);
    }

    [Fact]
    public async Task Delayed_disable_registers_task_and_disables_on_execution()
    {
        using var workspace = new TempWorkspace();
        var ethernet = new FakeEthernetController();
        var scheduler = new FakeScheduler();
        var clock = new FakeClock();
        var service = TestServiceFactory.Create(workspace, new FakeFirewallManager(), scheduler, clock, ethernet);

        var scheduled = await service.RunActionAsync(new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.ScheduleDelayedEthernetDisable,
            DelayMinutes = 10,
            Directions = BlockDirections.None
        }, "测试", "eth-delay");
        Assert.True(scheduled.Success, scheduled.Message);
        Assert.NotNull(scheduled.TaskId);
        Assert.Single(scheduler.Tasks);
        Assert.StartsWith("--execute-task=", scheduler.LastArguments);

        var state = workspace.CreateStore().ReadState().State;
        var task = Assert.Single(state.Tasks);
        Assert.Equal(ScheduledMode.DelayedEthernetDisable, task.Mode);
        Assert.Equal(ScheduledExecutionAction.EthernetDisable, task.ExecutionAction);
        Assert.Equal(RuleTargetKind.Ethernet, task.TargetKind);
        Assert.Equal("所有物理以太网适配器", task.Target);
        Assert.Empty(task.PlannedRules);
        Assert.False(state.Ethernet.IsDisabledByTool);
        Assert.True(ethernet.Adapters[0].AdminEnabled);

        var execution = await service.ExecuteScheduledTaskAsync(task.TaskId);
        Assert.True(execution.Success, execution.Message);
        Assert.False(ethernet.Adapters[0].AdminEnabled);
        state = workspace.CreateStore().ReadState().State;
        task = Assert.Single(state.Tasks);
        Assert.Equal(ScheduledTaskStatus.Succeeded, task.Status);
        Assert.True(state.Ethernet.IsDisabledByTool);
        Assert.Single(state.Ethernet.DisabledAdapters);
        Assert.Empty(scheduler.Tasks);
    }

    [Fact]
    public async Task Delayed_disable_rejects_another_pending_task()
    {
        using var workspace = new TempWorkspace();
        var ethernet = new FakeEthernetController();
        var scheduler = new FakeScheduler();
        var service = TestServiceFactory.Create(workspace, new FakeFirewallManager(), scheduler, new FakeClock(), ethernet);

        var first = await service.RunActionAsync(new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.ScheduleDelayedEthernetDisable,
            DelayMinutes = 10,
            Directions = BlockDirections.None
        }, "测试", "eth-delay-1");
        Assert.True(first.Success, first.Message);

        var second = await service.RunActionAsync(new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.ScheduleDelayedEthernetDisable,
            DelayMinutes = 20,
            Directions = BlockDirections.None
        }, "测试", "eth-delay-2");
        Assert.False(second.Success);
        Assert.Single(scheduler.Tasks);
        Assert.Single(workspace.CreateStore().ReadState().State.Tasks);
    }

    [Fact]
    public async Task Delayed_disable_rejects_when_ethernet_is_already_disabled()
    {
        using var workspace = new TempWorkspace();
        var ethernet = new FakeEthernetController();
        var service = TestServiceFactory.Create(workspace, new FakeFirewallManager(), new FakeScheduler(), new FakeClock(), ethernet);
        var immediate = await service.RunActionAsync(Action(ElevatedActionKind.DisableEthernet), "测试", "eth-now");
        Assert.True(immediate.Success, immediate.Message);

        var scheduled = await service.RunActionAsync(new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.ScheduleDelayedEthernetDisable,
            DelayMinutes = 10,
            Directions = BlockDirections.None
        }, "测试", "eth-delay-disabled");
        Assert.False(scheduled.Success);
        Assert.Empty(workspace.CreateStore().ReadState().State.Tasks);
    }
}
