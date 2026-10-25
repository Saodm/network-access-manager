namespace NetworkAccessManager.Core.Network;

using NetworkAccessManager.Core.Persistence;

/// <summary>
/// A physical Ethernet adapter as reported by Windows. AdminEnabled is only
/// populated when the value could be read from the elevated NetAdapter data;
/// a non-elevated UI may only know the operational status.
/// </summary>
public sealed class EthernetAdapterInfo
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string Description { get; init; } = string.Empty;
    public string StatusText { get; init; } = "未知";
    public string? MacAddress { get; init; }
    public bool? AdminEnabled { get; init; }

    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? Description : Name;
}

public sealed class EthernetChangeResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public IReadOnlyList<string> ChangedAdapterIds { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> FailedAdapterIds { get; init; } = Array.Empty<string>();
    public IReadOnlyList<EthernetAdapterInfo> Before { get; init; } = Array.Empty<EthernetAdapterInfo>();
    public IReadOnlyList<EthernetAdapterInfo> After { get; init; } = Array.Empty<EthernetAdapterInfo>();
}

public interface IEthernetController
{
    IReadOnlyList<EthernetAdapterInfo> Inspect();
    EthernetChangeResult Disable(IReadOnlyList<EthernetAdapterRecord> adapters);
    EthernetChangeResult Enable(IReadOnlyList<EthernetAdapterRecord> adapters);
}
