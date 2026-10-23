using System.Diagnostics;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Firewall;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;

namespace NetworkAccessManager.Tests;

public sealed class IntegrationFactAttribute : FactAttribute
{
    public IntegrationFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("NAM_RUN_INTEGRATION_TESTS") != "1")
            Skip = "设置环境变量 NAM_RUN_INTEGRATION_TESTS=1 后运行真实防火墙/任务计划集成测试。";
        else if (!WindowsPrivilege.IsAdministrator())
            Skip = "集成测试需要管理员权限。";
    }
}

public sealed class TempWorkspace : IDisposable
{
    public TempWorkspace(string prefix = "nam-test")
    {
        // The test runner in this environment has a restricted token for
        // %TEMP% even when the parent shell has full access. Keep test data
        // beside the test binaries so the suite is self-contained and removed
        // after each test.
        var baseDirectory = Path.Combine(AppContext.BaseDirectory, "test-work");
        Directory.CreateDirectory(baseDirectory);
        Root = Path.Combine(baseDirectory, $"{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Root);
        Paths = new AppPaths(Path.Combine(Root, "data"));
        Paths.EnsureDirectories();
        DummyExePath = Path.Combine(Root, "TestNetworkApp.exe");
        var source = Path.Combine(Environment.SystemDirectory, "where.exe");
        File.Copy(source, DummyExePath, overwrite: false);
    }

    public string Root { get; }
    public AppPaths Paths { get; }
    public string DummyExePath { get; }

    public StateRepository CreateStore() => new(Paths);

    public void Dispose()
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Directory.Delete(Root, recursive: true);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(100);
            }
            catch (UnauthorizedAccessException)
            {
                Thread.Sleep(100);
            }
        }
    }
}

public sealed class FakeClock : IClock
{
    public DateTimeOffset UtcNow { get; set; } = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);
    public void Advance(TimeSpan time) => UtcNow = UtcNow.Add(time);
}

public sealed class FakeScheduler : IScheduledTaskRegistrar
{
    private readonly Dictionary<string, DateTimeOffset> _tasks = new(StringComparer.OrdinalIgnoreCase);
    public bool FailRegistration { get; set; }
    public bool FailDeletion { get; set; }
    public string? LastArguments { get; private set; }
    public IReadOnlyDictionary<string, DateTimeOffset> Tasks => _tasks;

    public Task RegisterAsync(string taskName, string arguments, DateTimeOffset runAtUtc, string description, CancellationToken cancellationToken = default)
    {
        if (FailRegistration) throw new ScheduledTaskException("模拟计划任务注册失败。");
        _tasks[taskName] = runAtUtc;
        LastArguments = arguments;
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string taskName, CancellationToken cancellationToken = default) =>
        Task.FromResult(_tasks.ContainsKey(taskName));

    public Task DeleteAsync(string taskName, CancellationToken cancellationToken = default)
    {
        if (FailDeletion) throw new ScheduledTaskException("模拟计划任务删除失败。");
        _tasks.Remove(taskName);
        return Task.CompletedTask;
    }

    public Task<ScheduledTaskQueryResult> QueryAsync(string taskName, CancellationToken cancellationToken = default) =>
        Task.FromResult(new ScheduledTaskQueryResult { Exists = _tasks.ContainsKey(taskName), Accessible = true });
}

public sealed class FakeFirewallManager : IFirewallManager
{
    private readonly Dictionary<string, RuleDefinition> _rules = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _externalDeletes = new(StringComparer.OrdinalIgnoreCase);
    public bool IsElevated { get; set; } = true;
    public string? AvailabilityError { get; set; }
    public string? CreateError { get; set; }
    public bool ProfileDisabled { get; set; }
    public IReadOnlyCollection<string> RuleNames => _rules.Keys;

    public FirewallAvailability GetAvailability() => new()
    {
        IsAvailable = AvailabilityError is null,
        IsCurrentProfileProtected = AvailabilityError is null && !ProfileDisabled,
        CanReadRules = AvailabilityError is null,
        StatusText = AvailabilityError ?? "测试防火墙可用",
        Error = AvailabilityError ?? (ProfileDisabled ? "测试防火墙配置文件已关闭" : null),
        ProfilesSummary = "测试配置文件"
    };

    public FirewallInspectionBatch InspectRules(IReadOnlyList<ManagedRuleRecord> records)
    {
        var result = new Dictionary<string, FirewallRuleInspection>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in records)
        {
            if (_rules.TryGetValue(record.FirewallRuleName, out var rule))
            {
                var identity = rule.RuleId == record.RuleId && rule.Direction == record.Direction;
                var matches = identity && rule.Target == record.Target;
                result[record.RuleId] = new FirewallRuleInspection
                {
                    RuleId = record.RuleId,
                    FirewallRuleName = record.FirewallRuleName,
                    State = matches ? RuleInspectionState.Verified : RuleInspectionState.Mismatched,
                    IdentityMatches = identity,
                    Exists = true,
                    IsEnabled = true,
                    Direction = (int)rule.Direction,
                    Action = FirewallConstants.ActionBlock,
                    Detail = matches ? "测试规则一致" : "测试规则被外部修改",
                    Description = rule.Description
                };
            }
            else
            {
                result[record.RuleId] = new FirewallRuleInspection
                {
                    RuleId = record.RuleId,
                    FirewallRuleName = record.FirewallRuleName,
                    State = RuleInspectionState.Missing,
                    IdentityMatches = false,
                    Exists = false,
                    Detail = "测试规则不存在"
                };
            }
        }

        return new FirewallInspectionBatch
        {
            Inspections = result,
            Availability = GetAvailability(),
            CheckedUtc = DateTimeOffset.UtcNow
        };
    }

    public IReadOnlyList<FirewallRuleInspection> CreateRules(IReadOnlyList<RuleDefinition> definitions)
    {
        if (!IsElevated) throw new FirewallOperationException("测试模式需要管理员。");
        if (CreateError is not null) throw new FirewallOperationException(CreateError);
        foreach (var def in definitions)
        {
            if (_rules.ContainsKey(def.FirewallRuleName))
                throw new FirewallOperationException("测试规则重复。");
            _rules[def.FirewallRuleName] = def;
        }
        return definitions.Select(def => new FirewallRuleInspection
        {
            RuleId = def.RuleId,
            FirewallRuleName = def.FirewallRuleName,
            State = RuleInspectionState.Verified,
            IdentityMatches = true,
            Exists = true,
            IsEnabled = true,
            Direction = (int)def.Direction,
            Action = FirewallConstants.ActionBlock,
            Detail = "创建成功",
            Description = def.Description
        }).ToList();
    }

    public void RemoveRule(string firewallRuleName, string expectedRuleId)
    {
        if (!_rules.TryGetValue(firewallRuleName, out var rule))
            throw new FirewallOperationException("测试规则不存在。");
        if (rule.RuleId != expectedRuleId)
            throw new FirewallOperationException("测试规则身份不符。");
        _rules.Remove(firewallRuleName);
    }

    public IReadOnlyList<string> FindManagedOrphanRuleNames(ISet<string> knownRuleNames) =>
        _rules.Keys.Where(n => !knownRuleNames.Contains(n)).ToList();

    public void SimulateExternalDelete(string firewallRuleName) => _rules.Remove(firewallRuleName);

    public void SimulateExternalModify(string firewallRuleName)
    {
        if (_rules.TryGetValue(firewallRuleName, out var rule))
            _rules[firewallRuleName] = new RuleDefinition
            {
                RuleId = rule.RuleId,
                FirewallRuleName = rule.FirewallRuleName,
                Description = rule.Description,
                TargetKind = rule.TargetKind,
                Target = rule.Target + ".modified",
                Direction = rule.Direction
            };
    }
}

public static class TestServiceFactory
{
    public static NetworkControlService Create(
        TempWorkspace workspace,
        FakeFirewallManager firewall,
        FakeScheduler scheduler,
        FakeClock clock)
    {
        return new NetworkControlService(
            workspace.CreateStore(),
            firewall,
            scheduler,
            clock,
            NullAppLog.Instance,
            Path.Combine(workspace.Root, "NetworkAccessManager.exe"));
    }

    public static ElevatedAction BlockProgram(TempWorkspace workspace, BlockDirections directions = BlockDirections.Outbound) =>
        new()
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.BlockProgram,
            TargetKind = RuleTargetKind.Program,
            Target = workspace.DummyExePath,
            Directions = directions
        };
}
