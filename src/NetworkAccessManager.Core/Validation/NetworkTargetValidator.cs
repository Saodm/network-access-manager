using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace NetworkAccessManager.Core.Validation;

public sealed class NetworkTargetValidationResult
{
    public bool IsValid { get; init; }
    public string? Error { get; init; }
    public string? NormalizedTarget { get; init; }
    public string? Address { get; init; }
    public int? PrefixLength { get; init; }
    public AddressFamily AddressFamily { get; init; }
    public bool IsCidr { get; init; }
    public bool IsBroadScope { get; init; }
    public bool IsLoopback { get; init; }
    public bool IsMulticast { get; init; }
    public bool WasNormalized { get; init; }
    public string? Warning { get; init; }

    public static NetworkTargetValidationResult Invalid(string error) => new()
    {
        IsValid = false,
        Error = error
    };
}

/// <summary>
/// A deliberately strict parser for the only target formats supported by the MVP:
/// one IPv4/IPv6 address, or an IPv4/IPv6 CIDR prefix. Host bits in CIDR input
/// are normalized to the network address. Domains, ports, ranges and scoped
/// addresses are rejected rather than guessed at.
/// </summary>
public static partial class NetworkTargetValidator
{
    [GeneratedRegex(@"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$", RegexOptions.CultureInvariant)]
    private static partial Regex StrictIpv4Regex();

    [GeneratedRegex(@"^\d{1,3}$", RegexOptions.CultureInvariant)]
    private static partial Regex PrefixRegex();

    public static NetworkTargetValidationResult Validate(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return NetworkTargetValidationResult.Invalid("请输入 IP 地址或 CIDR 网段。");

        var text = input.Trim();
        if (text.Any(char.IsWhiteSpace))
            return NetworkTargetValidationResult.Invalid("目标中不能包含空白字符。");
        if (text.Contains('，') || text.Contains(','))
            return NetworkTargetValidationResult.Invalid("每次只能输入一个地址或网段。");
        if (text.Contains('%'))
            return NetworkTargetValidationResult.Invalid("不支持带作用域 ID 的 IPv6 地址（例如 %12）。");
        if (text.Contains("://", StringComparison.Ordinal))
            return NetworkTargetValidationResult.Invalid("请输入纯 IP 地址或 CIDR，不要包含协议、域名或端口。");

        var slashIndex = text.IndexOf('/');
        if (slashIndex >= 0 && text.IndexOf('/', slashIndex + 1) >= 0)
            return NetworkTargetValidationResult.Invalid("CIDR 中只能包含一个“/”。");

        var addressPart = slashIndex >= 0 ? text[..slashIndex] : text;
        var prefixPart = slashIndex >= 0 ? text[(slashIndex + 1)..] : null;

        if (string.IsNullOrWhiteSpace(addressPart))
            return NetworkTargetValidationResult.Invalid("“/”前面缺少 IP 地址。");
        if (slashIndex >= 0 && string.IsNullOrWhiteSpace(prefixPart))
            return NetworkTargetValidationResult.Invalid("“/”后面缺少前缀长度。");
        if (prefixPart is not null && !PrefixRegex().IsMatch(prefixPart))
            return NetworkTargetValidationResult.Invalid("CIDR 前缀长度必须是十进制正整数。");

        var looksIpv4 = addressPart.Contains('.');
        var looksIpv6 = addressPart.Contains(':');
        if (looksIpv4 && looksIpv6)
            return NetworkTargetValidationResult.Invalid("地址格式不明确，不能同时包含“.”和“:”。");
        if (!looksIpv4 && !looksIpv6)
            return NetworkTargetValidationResult.Invalid("只支持 IPv4、IPv6 地址或 CIDR 网段；不支持域名。");

        if (looksIpv4)
        {
            if (!StrictIpv4Regex().IsMatch(addressPart))
                return NetworkTargetValidationResult.Invalid("IPv4 地址格式无效（必须为 0-255 的四段十进制数字，且不允许前导零）。");
        }
        else
        {
            // IPAddress.TryParse is lenient in a few unusual cases; combining it
            // with a syntax sanity check avoids accepting host names as addresses.
            if (!addressPart.Contains(':'))
                return NetworkTargetValidationResult.Invalid("IPv6 地址格式无效。");
        }

        if (!IPAddress.TryParse(addressPart, out var address))
            return NetworkTargetValidationResult.Invalid("无法解析该 IP 地址。");

        if (address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            return NetworkTargetValidationResult.Invalid("只支持 IPv4 或 IPv6。");
        if (address.IsIPv4MappedToIPv6)
            return NetworkTargetValidationResult.Invalid("不支持 IPv4 映射的 IPv6 地址，请直接输入 IPv4 地址。");

        var isIpv4 = address.AddressFamily == AddressFamily.InterNetwork;
        var maxPrefix = isIpv4 ? 32 : 128;
        var isCidr = prefixPart is not null;
        var prefix = maxPrefix;
        if (isCidr)
        {
            if (!int.TryParse(prefixPart, out prefix) || prefix < 0 || prefix > maxPrefix)
                return NetworkTargetValidationResult.Invalid($"前缀长度必须在 0 到 {maxPrefix} 之间。");
        }

        if (!isCidr && (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)))
            return NetworkTargetValidationResult.Invalid("未指定地址（0.0.0.0 或 ::）不能作为单个阻断目标；如需表示全部地址，请明确输入 /0 网段。");

        var originalBytes = address.GetAddressBytes();
        var networkBytes = originalBytes.ToArray();
        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;
        if (remainingBits > 0 && fullBytes < networkBytes.Length)
            networkBytes[fullBytes] = (byte)(networkBytes[fullBytes] & (0xFF << (8 - remainingBits)));
        for (var i = fullBytes + (remainingBits > 0 ? 1 : 0); i < networkBytes.Length; i++)
            networkBytes[i] = 0;

        var normalizedAddress = new IPAddress(networkBytes);
        var wasNormalized = !originalBytes.SequenceEqual(networkBytes);
        var normalized = isCidr ? $"{normalizedAddress}/{prefix}" : normalizedAddress.ToString();

        var broad = prefix <= (isIpv4 ? 8 : 16);
        var loopbackPrefix = isIpv4 ? 8 : 128;
        var isLoopback = prefix >= loopbackPrefix && IsInPrefix(normalizedAddress, IPAddress.Loopback, loopbackPrefix);
        var isMulticast = normalizedAddress.IsIPv6Multicast || (isIpv4 && IsIpv4Multicast(networkBytes));

        var warningParts = new List<string>();
        if (broad)
            warningParts.Add(prefix == 0
                ? "该网段覆盖全部同类地址，可能中断几乎所有网络访问。"
                : "该网段范围很大，可能影响大量应用和网络访问。");
        if (isLoopback)
            warningParts.Add("目标包含本机回环地址，可能影响本机程序之间的通信。");
        if (isMulticast)
            warningParts.Add("目标包含组播地址，可能影响设备发现或流媒体功能。");
        if (wasNormalized)
            warningParts.Add($"主机位已按网络前缀归一化为 {normalized}。");

        return new NetworkTargetValidationResult
        {
            IsValid = true,
            NormalizedTarget = normalized,
            Address = normalizedAddress.ToString(),
            PrefixLength = prefix,
            AddressFamily = address.AddressFamily,
            IsCidr = isCidr,
            IsBroadScope = broad,
            IsLoopback = isLoopback,
            IsMulticast = isMulticast,
            WasNormalized = wasNormalized,
            Warning = warningParts.Count > 0 ? string.Join(" ", warningParts) : null
        };
    }

    private static bool IsIpv4Multicast(byte[] bytes) => bytes.Length == 4 && bytes[0] is >= 224 and <= 239;

    private static bool IsInPrefix(IPAddress address, IPAddress network, int prefix)
    {
        if (address.AddressFamily != network.AddressFamily) return false;
        var a = address.GetAddressBytes();
        var n = network.GetAddressBytes();
        var full = prefix / 8;
        var rem = prefix % 8;
        for (var i = 0; i < full; i++)
            if (a[i] != n[i]) return false;
        if (rem == 0) return true;
        var mask = (byte)(0xFF << (8 - rem));
        return (a[full] & mask) == (n[full] & mask);
    }
}
