using NetworkAccessManager.Core.Models;

namespace NetworkAccessManager.Core.Operations;

public enum ElevatedActionKind
{
    BlockProgram = 0,
    BlockNetworkAddress = 1,
    ScheduleDelayedBlock = 2,
    ScheduleDelayedUnblock = 3,
    ScheduleTimedBlock = 4,
    UnblockTarget = 5,
    CancelScheduledTask = 6
}

public sealed class ElevatedAction
{
    public string ActionId { get; set; } = Guid.NewGuid().ToString("N");
    public ElevatedActionKind Kind { get; set; }
    public RuleTargetKind TargetKind { get; set; }
    public string? Target { get; set; }
    public BlockDirections Directions { get; set; } = BlockDirections.Outbound;
    public int? DelayMinutes { get; set; }
    public string? TaskId { get; set; }
    public bool UnblockRulesOnCancel { get; set; }
}

public sealed class ElevatedRequest
{
    public int ProtocolVersion { get; set; } = 1;
    public string RequestId { get; set; } = Guid.NewGuid().ToString("N");
    public string UserSid { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public List<ElevatedAction> Actions { get; set; } = new();
}

public sealed class ElevatedActionResult
{
    public string ActionId { get; set; } = string.Empty;
    public bool Success { get; set; }
    public OperationOutcome Outcome { get; set; } = OperationOutcome.Failure;
    public string Message { get; set; } = string.Empty;
    public string? Detail { get; set; }
    public List<string> RuleIds { get; set; } = new();
    public string? TaskId { get; set; }
    public string? TaskName { get; set; }
    public DateTimeOffset? PlannedUtc { get; set; }
}

public sealed class ElevatedResponse
{
    public int ProtocolVersion { get; set; } = 1;
    public string RequestId { get; set; } = string.Empty;
    public bool SuccessOverall { get; set; }
    public string? FatalError { get; set; }
    public DateTimeOffset StartedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset CompletedUtc { get; set; } = DateTimeOffset.UtcNow;
    public List<ElevatedActionResult> Results { get; set; } = new();
}

public sealed class OperationTarget
{
    public RuleTargetKind TargetKind { get; init; }
    public string Target { get; init; } = string.Empty;
    public string DisplayTarget { get; init; } = string.Empty;
    public BlockDirections Directions { get; init; } = BlockDirections.Outbound;
    public int? Pid { get; init; }
}
