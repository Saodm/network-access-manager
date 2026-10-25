using NetworkAccessManager.Core.Models;

namespace NetworkAccessManager.Core.Persistence;

public sealed class AppState
{
    public int SchemaVersion { get; set; } = 1;
    public long Revision { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public List<ManagedRuleRecord> Rules { get; set; } = new();
    public List<ScheduledTaskRecord> Tasks { get; set; } = new();
    public List<OperationHistoryEvent> Events { get; set; } = new();
    public EthernetControlState Ethernet { get; set; } = new();
}

public sealed class EthernetControlState
{
    public bool IsDisabledByTool { get; set; }
    public DateTimeOffset? DisabledUtc { get; set; }
    public List<EthernetAdapterRecord> DisabledAdapters { get; set; } = new();
    public string? Note { get; set; }
}

public sealed class EthernetAdapterRecord
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

public sealed class ManagedRuleRecord
{
    public string RuleId { get; set; } = Guid.NewGuid().ToString("N");
    public RuleTargetKind TargetKind { get; set; }
    public string Target { get; set; } = string.Empty;
    public string DisplayTarget { get; set; } = string.Empty;
    public FirewallDirection Direction { get; set; }
    public string FirewallRuleName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ManagedRuleStatus Status { get; set; } = ManagedRuleStatus.Active;
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string CreatedBy { get; set; } = string.Empty;
    public string OperationGroupId { get; set; } = string.Empty;
    public DateTimeOffset? VerifiedUtc { get; set; }
    public string? Note { get; set; }
}

public sealed class PlannedRule
{
    public string RuleId { get; set; } = Guid.NewGuid().ToString("N");
    public string FirewallRuleName { get; set; } = string.Empty;
    public FirewallDirection Direction { get; set; }
}

public sealed class ScheduledTaskRecord
{
    public string TaskId { get; set; } = Guid.NewGuid().ToString("N");
    public ScheduledMode Mode { get; set; }
    public ScheduledExecutionAction ExecutionAction { get; set; }
    public ScheduledTaskStatus Status { get; set; } = ScheduledTaskStatus.Pending;
    public RuleTargetKind TargetKind { get; set; }
    public string Target { get; set; } = string.Empty;
    public string DisplayTarget { get; set; } = string.Empty;
    public BlockDirections Directions { get; set; }
    public List<PlannedRule> PlannedRules { get; set; } = new();
    public string ScheduledTaskName { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset PlannedUtc { get; set; }
    public DateTimeOffset? StartedUtc { get; set; }
    public DateTimeOffset? CompletedUtc { get; set; }
    public DateTimeOffset? LastObservedUtc { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public string? FailureReason { get; set; }
    public string? ResultMessage { get; set; }
    public string? CorrelationId { get; set; }

    public string ModeText => Mode switch
    {
        ScheduledMode.DelayedBlock => "延迟禁止",
        ScheduledMode.DelayedUnblock => "延迟解除",
        ScheduledMode.TimedBlock => "限时禁止",
        _ => "未知"
    };

    public string StatusText => Status switch
    {
        ScheduledTaskStatus.Pending => "等待执行",
        ScheduledTaskStatus.Running => "执行中",
        ScheduledTaskStatus.Succeeded => "已完成",
        ScheduledTaskStatus.Failed => "执行失败",
        ScheduledTaskStatus.Cancelled => "已取消",
        _ => "未知"
    };
}

public sealed class OperationHistoryEvent
{
    public string EventId { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Operation { get; set; } = string.Empty;
    public RuleTargetKind? TargetKind { get; set; }
    public string? Target { get; set; }
    public int? Pid { get; set; }
    public string? TargetPath { get; set; }
    public string? RuleId { get; set; }
    public string? TaskId { get; set; }
    public DateTimeOffset? PlannedUtc { get; set; }
    public DateTimeOffset? ActualUtc { get; set; }
    public OperationOutcome Outcome { get; set; } = OperationOutcome.Info;
    public string Message { get; set; } = string.Empty;
    public string? Detail { get; set; }
    public string Source { get; set; } = "应用";
    public string? CorrelationId { get; set; }
}

public sealed class StoreReadResult
{
    public AppState State { get; init; } = new();
    public bool UsedBackup { get; init; }
    public bool Existed { get; init; }
    public string? Warning { get; init; }
}

public sealed class UiSettings
{
    public int RefreshIntervalSeconds { get; set; } = 5;
    public bool AutoRefreshEnabled { get; set; } = true;
    public bool ShowConfirmationDetails { get; set; } = true;
    public int HistoryRetentionDays { get; set; } = 90;
}
