using System.Net.NetworkInformation;

namespace NetworkAccessManager.Core.Network;

/// <summary>
/// Read-only, non-elevated Ethernet enumeration for the UI. Physical/virtual
/// filtering is deliberately conservative: only Ethernet media types are shown
/// and common virtual/VPN adapters are excluded.
/// </summary>
public static class EthernetAdapterInspector
{
    private static readonly string[] VirtualKeywords =
    [
        "virtual", "hyper-v", "vmware", "virtualbox", "vpn", "tap", "loopback",
        "bluetooth", "wi-fi", "wireless", "wan miniport", "teredo", "kernel debug",
        "npcap", "wintun", "wireguard", "openvpn", "qos", "wfp", "packet scheduler",
        "native mac", "mac layer", "lightweight filter"
    ];

    public static IReadOnlyList<EthernetAdapterInfo> Inspect()
    {
        var result = new List<EthernetAdapterInfo>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!IsEthernet(adapter.NetworkInterfaceType)) continue;
            var mac = adapter.GetPhysicalAddress();
            if (mac.GetAddressBytes().Length < 6) continue;
            var description = adapter.Description ?? string.Empty;
            if (VirtualKeywords.Any(keyword =>
                    description.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    adapter.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
                continue;

            result.Add(new EthernetAdapterInfo
            {
                Id = NormalizeId(adapter.Id),
                Name = adapter.Name,
                Description = description,
                StatusText = StatusText(adapter.OperationalStatus),
                MacAddress = mac.ToString(),
                AdminEnabled = null
            });
        }
        return result
            .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    public static string NormalizeId(string? id) =>
        string.IsNullOrWhiteSpace(id) ? string.Empty : id.Trim().Trim('{', '}').ToUpperInvariant();

    private static bool IsEthernet(NetworkInterfaceType type) => type is
        NetworkInterfaceType.Ethernet or
        NetworkInterfaceType.GigabitEthernet or
        NetworkInterfaceType.FastEthernetFx or
        NetworkInterfaceType.FastEthernetT or
        NetworkInterfaceType.Ethernet3Megabit;

    private static string StatusText(OperationalStatus status) => status switch
    {
        OperationalStatus.Up => "已连接",
        OperationalStatus.Down => "未连接/已禁用",
        OperationalStatus.Dormant => "休眠",
        OperationalStatus.NotPresent => "不存在",
        OperationalStatus.LowerLayerDown => "下层断开",
        _ => status.ToString()
    };
}
