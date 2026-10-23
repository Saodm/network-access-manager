using System.Diagnostics;
using System.Runtime.InteropServices;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Firewall;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Scheduling;
using NetworkAccessManager.Core.Services;

namespace NetworkAccessManager.Tests;

public sealed class MonitoringIntegrationTests
{
    [Fact]
    public void Real_process_and_network_snapshot_is_consistent()
    {
        var log = NullAppLog.Instance;
        var processService = new ProcessSnapshotService(log);
        var snapshot = processService.Capture(Environment.ProcessPath);
        Assert.Null(snapshot.Error);
        Assert.NotEmpty(snapshot.Processes);

        var current = snapshot.Processes.FirstOrDefault(p => p.Pid == Environment.ProcessId);
        Assert.NotNull(current);
        Assert.False(string.IsNullOrWhiteSpace(current!.ExecutablePath));
        Assert.True(current.IsProgramBlockProtected, "当前测试进程应被识别为本工具自身相关路径从而受保护。");

        var networkService = new NetworkConnectionService(log);
        var network = networkService.Capture(snapshot.Processes);
        Assert.Null(network.Error);
        Assert.True(network.Connections.Count > 0, "当前测试环境应至少有监听端口。");
        Assert.Equal(network.Connections.Count(c => !c.ProcessResolved), network.UnknownProcessCount);

        var pidSet = snapshot.Processes.Select(p => p.Pid).ToHashSet();
        foreach (var connection in network.Connections)
        {
            Assert.InRange(connection.LocalPort, 0, 65535);
            Assert.False(string.IsNullOrWhiteSpace(connection.LocalAddress));
            Assert.InRange(connection.OwningPid, 0, int.MaxValue);
            if (connection.ProcessResolved)
            {
                Assert.Contains(connection.OwningPid, pidSet);
                Assert.False(string.IsNullOrWhiteSpace(connection.ProcessName));
            }
            else
            {
                Assert.Null(connection.ProcessName);
                Assert.Contains("未知进程", connection.OwnerText);
            }
            if (connection.OwningPid == 0)
                Assert.False(connection.ProcessResolved, "PID 0 的 TIME_WAIT/无主端点不得关联到 System Idle Process。");
        }

        Assert.True(network.TcpCount > 0);
        Assert.Equal(network.TcpCount + network.UdpCount, network.Connections.Count);
        Assert.Contains(network.Connections, c => c.Protocol == NetworkProtocol.Tcp && c.IsListening);
    }
}

[Trait("Category", "Integration")]
public sealed class FirewallIntegrationTests
{
    [IntegrationFact]
    public void Real_firewall_rule_is_created_verified_and_removed_without_touching_other_rules()
    {
        using var workspace = new TempWorkspace();
        var manager = new ComFirewallManager();
        Assert.True(manager.IsElevated, "集成测试需要管理员权限。");
        var availability = manager.GetAvailability();
        Assert.True(availability.IsAvailable, availability.Error);
        Assert.True(availability.IsCurrentProfileProtected, availability.Error);
        Assert.True(availability.CanReadRules);

        var ruleId = Guid.NewGuid().ToString("N");
        var metadata = FirewallRuleMetadata.Create(
            ruleId,
            FirewallDirection.Outbound,
            RuleTargetKind.Program,
            workspace.DummyExePath,
            System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,
            DateTimeOffset.UtcNow);
        var name = FirewallRuleMetadata.BuildRuleName(ruleId, FirewallDirection.Outbound);
        var definition = new RuleDefinition
        {
            RuleId = ruleId,
            FirewallRuleName = name,
            Description = metadata.ToDescription(),
            TargetKind = RuleTargetKind.Program,
            Target = workspace.DummyExePath,
            Direction = FirewallDirection.Outbound
        };
        var record = new ManagedRuleRecord
        {
            RuleId = ruleId,
            TargetKind = RuleTargetKind.Program,
            Target = workspace.DummyExePath,
            Direction = FirewallDirection.Outbound,
            FirewallRuleName = name,
            Description = definition.Description,
            Status = ManagedRuleStatus.Active
        };

        var preexisting = ReadSomeRuleName();
        var created = false;
        try
        {
            var inspections = manager.CreateRules(new[] { definition });
            created = true;
            Assert.Single(inspections);
            Assert.Equal(RuleInspectionState.Verified, inspections[0].State);

            var independent = ReadRuleDirect(name);
            Assert.True(independent.Exists, "独立 COM 读取应能看到新规则。");
            Assert.Equal(0, independent.Action);
            Assert.Equal(2, independent.Direction);
            Assert.Equal(FirewallConstants.ProtocolAny, independent.Protocol);
            Assert.Equal(workspace.DummyExePath, independent.ApplicationName);
            Assert.True(independent.Enabled);

            var inspection = manager.InspectRules(new[] { record }).Inspections[ruleId];
            Assert.Equal(RuleInspectionState.Verified, inspection.State);
            Assert.True(inspection.IdentityMatches);

            Assert.Throws<FirewallOperationException>(() => manager.RemoveRule(name, Guid.NewGuid().ToString("N")));
            Assert.True(ReadRuleDirect(name).Exists, "身份不匹配时不得删除规则。");

            manager.RemoveRule(name, ruleId);
            created = false;
            Assert.False(ReadRuleDirect(name).Exists);
            Assert.False(string.IsNullOrWhiteSpace(preexisting));
            Assert.True(ReadRuleDirect(preexisting!).Exists, "其他软件的规则不应受影响。");
        }
        finally
        {
            if (created)
            {
                try { manager.RemoveRule(name, ruleId); } catch { }
            }
        }
    }

    [IntegrationFact]
    public void Real_network_target_rule_has_no_program_scope_and_is_removable()
    {
        using var workspace = new TempWorkspace();
        var manager = new ComFirewallManager();
        var target = "203.0.113.0/24";
        var ruleId = Guid.NewGuid().ToString("N");
        var metadata = FirewallRuleMetadata.Create(
            ruleId,
            FirewallDirection.Outbound,
            RuleTargetKind.NetworkAddress,
            target,
            System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,
            DateTimeOffset.UtcNow);
        var name = FirewallRuleMetadata.BuildRuleName(ruleId, FirewallDirection.Outbound);
        var definition = new RuleDefinition
        {
            RuleId = ruleId,
            FirewallRuleName = name,
            Description = metadata.ToDescription(),
            TargetKind = RuleTargetKind.NetworkAddress,
            Target = target,
            Direction = FirewallDirection.Outbound
        };
        var created = false;
        try
        {
            manager.CreateRules(new[] { definition });
            created = true;
            var direct = ReadRuleDirect(name);
            Assert.True(direct.Exists);
            Assert.Equal(target, direct.RemoteAddresses);
            Assert.True(string.IsNullOrWhiteSpace(direct.ApplicationName), "目标规则不应绑定到某个程序路径。");
            manager.RemoveRule(name, ruleId);
            created = false;
            Assert.False(ReadRuleDirect(name).Exists);
        }
        finally
        {
            if (created)
            {
                try { manager.RemoveRule(name, ruleId); } catch { }
            }
        }
    }

    private sealed record RuleDirect(bool Exists, int Action, int Direction, int Protocol, bool Enabled, string? ApplicationName, string? RemoteAddresses);

    private static RuleDirect ReadRuleDirect(string ruleName)
    {
        RuleDirect? result = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2") ?? throw new InvalidOperationException("No firewall COM");
                dynamic policy = Activator.CreateInstance(type)!;
                try
                {
                    foreach (dynamic rule in policy.Rules)
                    {
                        string? name = Convert.ToString(rule.Name);
                        if (!string.Equals(name, ruleName, StringComparison.OrdinalIgnoreCase)) continue;
                        result = new RuleDirect(
                            true,
                            Convert.ToInt32(rule.Action),
                            Convert.ToInt32(rule.Direction),
                            Convert.ToInt32(rule.Protocol),
                            Convert.ToBoolean(rule.Enabled),
                            Convert.ToString(rule.ApplicationName),
                            Convert.ToString(rule.RemoteAddresses));
                        return;
                    }
                    result = new RuleDirect(false, 0, 0, 0, false, null, null);
                }
                finally
                {
                    if (Marshal.IsComObject(policy)) Marshal.FinalReleaseComObject(policy);
                }
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "独立 COM 读取超时。");
        if (failure is not null) throw new InvalidOperationException(failure.Message, failure);
        return result ?? throw new InvalidOperationException("未能读取防火墙规则。");
    }

    private static string? ReadSomeRuleName()
    {
        string? found = null;
        var thread = new Thread(() =>
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (type is null) return;
            dynamic policy = Activator.CreateInstance(type)!;
            try
            {
                foreach (dynamic rule in policy.Rules)
                {
                    var name = Convert.ToString(rule.Name);
                    if (!string.IsNullOrWhiteSpace(name) && !name!.StartsWith("NAM_", StringComparison.Ordinal))
                    {
                        found = name;
                        return;
                    }
                }
            }
            finally
            {
                if (Marshal.IsComObject(policy)) Marshal.FinalReleaseComObject(policy);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join(TimeSpan.FromSeconds(30));
        return found;
    }
}

[Trait("Category", "Integration")]
public sealed class ScheduledTaskIntegrationTests
{
    [IntegrationFact]
    public async Task Real_scheduled_task_can_be_registered_verified_and_deleted()
    {
        using var workspace = new TempWorkspace();
        var executable = Environment.ProcessPath;
        Assert.False(string.IsNullOrWhiteSpace(executable));
        var registrar = new TaskSchedulerRegistrar(workspace.Paths, executable!, NullAppLog.Instance);
        var taskId = Guid.NewGuid().ToString("N");
        var taskName = TaskNamePolicy.ForTask(taskId);
        var runAt = DateTimeOffset.UtcNow.AddMinutes(30);

        try
        {
            await registrar.RegisterAsync(
                taskName,
                $"--execute-task={taskId}",
                runAt,
                "NetworkAccessManager 集成测试任务，不应实际运行",
                CancellationToken.None);
            Assert.True(await registrar.ExistsAsync(taskName));
            var query = await registrar.QueryAsync(taskName);
            Assert.True(query.Exists, query.Error);
            await Assert.ThrowsAsync<ScheduledTaskException>(async () =>
                await registrar.DeleteAsync("Other_Task_0123456789abcdef0123456789abcdef"));
        }
        finally
        {
            try { await registrar.DeleteAsync(taskName); } catch { }
        }

        Assert.False(await registrar.ExistsAsync(taskName));
    }
}
