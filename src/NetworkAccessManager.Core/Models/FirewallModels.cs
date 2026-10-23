namespace NetworkAccessManager.Core.Models;

public static class FirewallConstants
{
    public const string ManagedGroup = "Network Access Manager 受管规则";
    public const string RuleNamePrefix = "NAM_";
    public const string MetadataPrefix = "NAMv1|";
    public const int ProfileAll = 0x7FFFFFFF;
    public const int ProtocolAny = 256;
    public const int ActionBlock = 0;
    public const int ActionAllow = 1;
}

public sealed class FirewallAvailability
{
    public bool IsAvailable { get; init; }
    public bool IsCurrentProfileProtected { get; init; }
    public bool CanReadRules { get; init; }
    public bool IsAccessLimited { get; init; }
    public string StatusText { get; init; } = "未知";
    public string? Error { get; init; }
    public string ProfilesSummary { get; init; } = "未知";
    public int? ManagedRuleCount { get; init; }

    public static FirewallAvailability Unknown(string error) => new()
    {
        StatusText = "未知",
        Error = error,
        ProfilesSummary = "未知"
    };
}

public enum RuleInspectionState
{
    Verified = 0,
    Missing = 1,
    Mismatched = 2,
    Unknown = 3
}

public sealed class FirewallRuleInspection
{
    public required string RuleId { get; init; }
    public required string FirewallRuleName { get; init; }
    public RuleInspectionState State { get; init; }
    public string Detail { get; init; } = string.Empty;
    public bool IdentityMatches { get; init; }
    public bool Exists { get; init; }
    public bool IsEnabled { get; init; }
    public int? Direction { get; init; }
    public int? Action { get; init; }
    public string? ApplicationName { get; init; }
    public string? RemoteAddresses { get; init; }
    public string? Grouping { get; init; }
    public string? Description { get; init; }
}

public sealed class FirewallInspectionBatch
{
    public IReadOnlyDictionary<string, FirewallRuleInspection> Inspections { get; init; } =
        new Dictionary<string, FirewallRuleInspection>(StringComparer.OrdinalIgnoreCase);
    public FirewallAvailability Availability { get; init; } = FirewallAvailability.Unknown("未检查");
    public DateTimeOffset CheckedUtc { get; init; }
}
