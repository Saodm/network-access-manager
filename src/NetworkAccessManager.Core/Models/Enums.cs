namespace NetworkAccessManager.Core.Models;

public enum RuleTargetKind
{
    Program = 0,
    NetworkAddress = 1,
    Ethernet = 2
}

[Flags]
public enum BlockDirections
{
    None = 0,
    Outbound = 1,
    Inbound = 2,
    Both = Outbound | Inbound
}

/// <summary>Values intentionally match NET_FW_RULE_DIRECTION.</summary>
public enum FirewallDirection
{
    Inbound = 1,
    Outbound = 2
}

public enum ManagedRuleStatus
{
    Active = 0,
    RemovedByUser = 1,
    RemovedExternally = 2,
    CreationFailed = 3
}

public enum ScheduledMode
{
    DelayedBlock = 0,
    DelayedUnblock = 1,
    TimedBlock = 2,
    DelayedEthernetDisable = 3
}

public enum ScheduledTaskStatus
{
    Pending = 0,
    Running = 1,
    Succeeded = 2,
    Failed = 3,
    Cancelled = 4
}

public enum ScheduledExecutionAction
{
    Block = 0,
    Unblock = 1,
    EthernetDisable = 2
}

public enum OperationOutcome
{
    Info = 0,
    Success = 1,
    Warning = 2,
    Failure = 3
}

public enum ProcessCategory
{
    UserApplication = 0,
    WindowsService = 1,
    WindowsComponent = 2,
    SystemCritical = 3,
    Unknown = 4
}

public enum RiskLevel
{
    Normal = 0,
    Caution = 1,
    High = 2,
    Critical = 3
}

public enum SignatureState
{
    Unknown = 0,
    NotSigned = 1,
    Valid = 2,
    Invalid = 3,
    Unavailable = 4
}

public enum NetworkProtocol
{
    Tcp = 0,
    Udp = 1
}

public enum IpVersion
{
    IPv4 = 0,
    IPv6 = 1
}

public enum NetworkActivityLevel
{
    None = 0,
    Listening = 1,
    Active = 2
}
