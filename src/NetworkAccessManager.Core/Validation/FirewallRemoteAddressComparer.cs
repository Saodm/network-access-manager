using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace NetworkAccessManager.Core.Validation;

/// <summary>
/// Windows Firewall normalizes some IPv4 CIDR remote addresses into the
/// equivalent address/netmask form (for example 203.0.113.0/24 becomes
/// 203.0.113.0/255.255.255.0). Verification must compare the represented
/// network, not the exact input spelling. This parser accepts a single network
/// entry only; the application never writes comma-separated or range targets.
/// </summary>
public static class FirewallRemoteAddressComparer
{
    public static bool Matches(string? actual, string? expected)
    {
        var validated = NetworkTargetValidator.Validate(expected);
        if (!validated.IsValid || validated.Address is null) return false;
        if (!IPAddress.TryParse(validated.Address, out var expectedAddress)) return false;

        var expectedPrefix = validated.PrefixLength ??
                             (expectedAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
        if (!TryParseActual(actual, out var actualAddress, out var actualPrefix)) return false;
        if (actualAddress.AddressFamily != expectedAddress.AddressFamily) return false;
        if (actualPrefix != expectedPrefix) return false;
        return MaskedEquals(actualAddress, expectedAddress, actualPrefix);
    }

    private static bool TryParseActual(string? text, out IPAddress address, out int prefix)
    {
        address = IPAddress.None;
        prefix = -1;
        if (string.IsNullOrWhiteSpace(text)) return false;

        var trimmed = text.Trim();
        if (trimmed.Contains(',')) return false;

        var slash = trimmed.IndexOf('/');
        if (slash < 0)
        {
            if (!IPAddress.TryParse(trimmed, out var single)) return false;
            address = single;
            prefix = single.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            return true;
        }

        if (trimmed.IndexOf('/', slash + 1) >= 0) return false;
        var addressPart = trimmed[..slash].Trim();
        var prefixPart = trimmed[(slash + 1)..].Trim();
        if (!IPAddress.TryParse(addressPart, out var parsedAddress)) return false;

        var maxPrefix = parsedAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out var numericPrefix))
        {
            if (numericPrefix < 0 || numericPrefix > maxPrefix) return false;
            address = parsedAddress;
            prefix = numericPrefix;
            return true;
        }

        if (!IPAddress.TryParse(prefixPart, out var maskAddress)) return false;
        if (maskAddress.AddressFamily != parsedAddress.AddressFamily) return false;
        var maskPrefix = ConvertMaskToPrefix(maskAddress.GetAddressBytes());
        if (maskPrefix < 0) return false;
        address = parsedAddress;
        prefix = maskPrefix;
        return true;
    }

    private static int ConvertMaskToPrefix(byte[] mask)
    {
        var prefix = 0;
        var zeroSeen = false;
        foreach (var value in mask)
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                var set = (value & (1 << bit)) != 0;
                if (set)
                {
                    if (zeroSeen) return -1;
                    prefix++;
                }
                else
                {
                    zeroSeen = true;
                }
            }
        }
        return prefix;
    }

    private static bool MaskedEquals(IPAddress left, IPAddress right, int prefix)
    {
        var a = left.GetAddressBytes();
        var b = right.GetAddressBytes();
        if (a.Length != b.Length) return false;

        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;
        for (var i = 0; i < fullBytes; i++)
            if (a[i] != b[i]) return false;

        if (remainingBits == 0) return true;
        var mask = (byte)(0xFF << (8 - remainingBits));
        return (a[fullBytes] & mask) == (b[fullBytes] & mask);
    }
}
