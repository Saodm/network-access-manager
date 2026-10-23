using System.Net;
using System.Net.Sockets;

namespace NetworkAccessManager.Core.Validation;

/// <summary>
/// Matches a remote endpoint against a single managed CIDR/address rule for
/// display purposes only. Rules in Windows Firewall remain authoritative.
/// </summary>
public static class NetworkAddressMatcher
{
    public static bool Matches(string? managedTarget, string? remoteAddress)
    {
        if (string.IsNullOrWhiteSpace(managedTarget) || string.IsNullOrWhiteSpace(remoteAddress))
            return false;

        var normalized = NetworkTargetValidator.Validate(managedTarget);
        if (!normalized.IsValid || normalized.Address is null) return false;
        if (!IPAddress.TryParse(remoteAddress, out var remote)) return false;
        if (!IPAddress.TryParse(normalized.Address, out var network)) return false;
        if (remote.AddressFamily != network.AddressFamily) return false;

        var prefix = normalized.PrefixLength ?? (network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
        return IsInPrefix(remote, network, prefix);
    }

    private static bool IsInPrefix(IPAddress address, IPAddress network, int prefix)
    {
        var a = address.GetAddressBytes();
        var n = network.GetAddressBytes();
        if (a.Length != n.Length) return false;
        var full = prefix / 8;
        var rem = prefix % 8;
        for (var i = 0; i < full; i++)
            if (a[i] != n[i]) return false;
        if (rem == 0) return true;
        var mask = (byte)(0xFF << (8 - rem));
        return (a[full] & mask) == (n[full] & mask);
    }
}

public static class TimeDisplay
{
    public static string LocalDateTime(DateTimeOffset? value) =>
        value is null ? "—" : value.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public static string LocalDateTimeShort(DateTimeOffset? value) =>
        value is null ? "—" : value.Value.ToLocalTime().ToString("MM-dd HH:mm:ss");

    public static string UtcIso(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O");
}
