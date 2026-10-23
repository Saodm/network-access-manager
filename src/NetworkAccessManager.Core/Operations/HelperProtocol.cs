using System.Text;
using System.Text.Json;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.Core.Operations;

public static class HelperProtocol
{
    public const string ElevatedRequestArgument = "--elevated-request=";
    public const string ExecuteTaskArgument = "--execute-task=";
    public const string ProbeArgument = "--probe";
    public const int MaxBase64RequestLength = 128 * 1024;
}

public static class HelperRequestCodec
{
    public static string Encode(ElevatedRequest request)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(request, JsonDefaults.CompactOptions);
        return Convert.ToBase64String(json, Base64FormattingOptions.None)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static ElevatedRequest Decode(string encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded))
            throw new FormatException("请求内容为空。");
        if (encoded.Length > HelperProtocol.MaxBase64RequestLength)
            throw new FormatException("请求内容过长。");

        var normalized = encoded.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4) % 4, '=');
        var bytes = Convert.FromBase64String(normalized);
        var request = JsonSerializer.Deserialize<ElevatedRequest>(bytes, JsonDefaults.CompactOptions)
                      ?? throw new FormatException("请求 JSON 为空。");
        return request;
    }

    public static void WriteResult(AppPaths paths, ElevatedResponse response)
    {
        paths.EnsureDirectories();
        var target = paths.ResultFilePath(response.RequestId);
        var temp = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var json = JsonSerializer.Serialize(response, JsonDefaults.Options);
        using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 16 * 1024, FileOptions.WriteThrough))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
        {
            writer.Write(json);
            writer.Flush();
            stream.Flush(true);
        }
        File.Move(temp, target, overwrite: true);
    }

    public static ElevatedResponse? TryReadResult(AppPaths paths, string requestId)
    {
        try
        {
            var path = paths.ResultFilePath(requestId);
            if (!File.Exists(path)) return null;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            return JsonSerializer.Deserialize<ElevatedResponse>(json, JsonDefaults.Options);
        }
        catch
        {
            return null;
        }
    }

    public static void TryDeleteResult(AppPaths paths, string requestId)
    {
        try
        {
            var path = paths.ResultFilePath(requestId);
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // Best effort cleanup.
        }
    }
}

public sealed class SchedulePlan
{
    public required string TaskName { get; init; }
    public required DateTimeOffset PlannedUtc { get; init; }
    public required string XmlFilePath { get; init; }
    public required string XmlContent { get; init; }
}

public interface IScheduledTaskRegistrar
{
    Task RegisterAsync(string taskName, string arguments, DateTimeOffset runAtUtc, string description, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(string taskName, CancellationToken cancellationToken = default);
    Task DeleteAsync(string taskName, CancellationToken cancellationToken = default);
    Task<ScheduledTaskQueryResult> QueryAsync(string taskName, CancellationToken cancellationToken = default);
}

public sealed class ScheduledTaskQueryResult
{
    public bool Exists { get; init; }
    public bool Accessible { get; init; }
    public string? Error { get; init; }
    public string? Detail { get; init; }
}

public sealed class ScheduledTaskException : Exception
{
    public ScheduledTaskException(string message, Exception? inner = null) : base(message, inner) { }
}

public interface IFirewallManager
{
    bool IsElevated { get; }
    FirewallAvailability GetAvailability();
    FirewallInspectionBatch InspectRules(IReadOnlyList<ManagedRuleRecord> records);
    IReadOnlyList<FirewallRuleInspection> CreateRules(IReadOnlyList<RuleDefinition> definitions);
    void RemoveRule(string firewallRuleName, string expectedRuleId);
    IReadOnlyList<string> FindManagedOrphanRuleNames(ISet<string> knownRuleNames);
}

public sealed class RuleDefinition
{
    public required string RuleId { get; init; }
    public required string FirewallRuleName { get; init; }
    public required string Description { get; init; }
    public required RuleTargetKind TargetKind { get; init; }
    public required string Target { get; init; }
    public required FirewallDirection Direction { get; init; }
}

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public static readonly SystemClock Instance = new();
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
