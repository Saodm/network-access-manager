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
}
