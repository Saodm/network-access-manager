using System.Globalization;
using System.Text;
using NetworkAccessManager.Core.Models;

namespace NetworkAccessManager.Core.Firewall;

public sealed record FirewallRuleMetadata(
    string RuleId,
    FirewallDirection Direction,
    RuleTargetKind TargetKind,
    string Target,
    string OwnerSid,
    DateTimeOffset CreatedUtc)
{
    // A vertical bar is rejected by the Windows Firewall COM API for the
    // Description property (verified on Windows 10 22H2), so use semicolons.
    public const string Prefix = "NAMv1;";

    public string ToDescription() =>
        $"{Prefix}id={RuleId};dir={Direction};kind={TargetKind};target={Base64UrlEncode(Target)};created={CreatedUtc.ToUniversalTime():O};owner={OwnerSid}";

    public static string BuildRuleName(string ruleId, FirewallDirection direction) =>
        $"{FirewallConstants.RuleNamePrefix}{ruleId}_{(direction == FirewallDirection.Outbound ? "OUT" : "IN")}";

    public static FirewallRuleMetadata Create(
        string ruleId,
        FirewallDirection direction,
        RuleTargetKind kind,
        string target,
        string ownerSid,
        DateTimeOffset createdUtc) =>
        new(ruleId, direction, kind, target, ownerSid, createdUtc);

    public static bool TryParse(string? description, out FirewallRuleMetadata? metadata)
    {
        metadata = null;
        if (string.IsNullOrWhiteSpace(description) ||
            !description.StartsWith(Prefix, StringComparison.Ordinal))
            return false;

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in description[Prefix.Length..].Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var split = segment.IndexOf('=');
            if (split <= 0 || split == segment.Length - 1) continue;
            values[segment[..split]] = segment[(split + 1)..];
        }

        if (!values.TryGetValue("id", out var id) ||
            !Guid.TryParseExact(id, "N", out _) ||
            !values.TryGetValue("dir", out var dirText) ||
            !Enum.TryParse<FirewallDirection>(dirText, ignoreCase: true, out var direction) ||
            !values.TryGetValue("kind", out var kindText) ||
            !Enum.TryParse<RuleTargetKind>(kindText, ignoreCase: true, out var kind) ||
            !values.TryGetValue("target", out var encodedTarget))
            return false;

        string target;
        try
        {
            target = Base64UrlDecode(encodedTarget);
        }
        catch
        {
            return false;
        }

        values.TryGetValue("owner", out var owner);
        DateTimeOffset created = default;
        if (values.TryGetValue("created", out var createdText))
            DateTimeOffset.TryParse(createdText, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out created);

        metadata = new FirewallRuleMetadata(id, direction, kind, target, owner ?? string.Empty, created);
        return true;
    }

    private static string Base64UrlEncode(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string Base64UrlDecode(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4) % 4, '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
    }
}
