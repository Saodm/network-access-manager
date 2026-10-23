namespace NetworkAccessManager.Core.Models;

public sealed class NetworkConnectionRecord
{
    public required string ConnectionId { get; init; }
    public NetworkProtocol Protocol { get; init; }
    public IpVersion IpVersion { get; init; }
    public int OwningPid { get; init; }
    public bool ProcessResolved { get; init; }
    public string? ProcessName { get; init; }
    public string? ProcessPath { get; init; }
    public required string LocalAddress { get; init; }
    public int LocalPort { get; init; }
    public string? RemoteAddress { get; init; }
    public int? RemotePort { get; init; }
    public int? TcpStateCode { get; init; }
    public string TcpStateText { get; init; } = "—";
    public bool IsListening { get; init; }
    public NetworkActivityLevel ActivityLevel { get; init; }
    public string? ScopeNote { get; init; }
    public DateTimeOffset CapturedUtc { get; init; }

    public string ProtocolText => Protocol == NetworkProtocol.Tcp ? "TCP" : "UDP";
    public string IpVersionText => IpVersion == IpVersion.IPv4 ? "IPv4" : "IPv6";
    public string OwnerText => ProcessResolved
        ? (string.IsNullOrWhiteSpace(ProcessName) ? "(未命名)" : ProcessName!)
        : $"未知进程 (PID {OwningPid})";
    public string LocalEndpoint => LocalPort > 0 ? $"{LocalAddress}:{LocalPort}" : LocalAddress;
    public string RemoteEndpoint => RemotePort is > 0 && !string.IsNullOrWhiteSpace(RemoteAddress)
        ? $"{RemoteAddress}:{RemotePort}"
        : "—";

    public string LocalEndpointWithScope => string.IsNullOrWhiteSpace(ScopeNote)
        ? LocalEndpoint
        : $"{LocalAddress}%{ScopeNote}:{LocalPort}";

    public string ActivityText => ActivityLevel switch
    {
        NetworkActivityLevel.Active => IsListening ? "监听 / 活动" : "已连接",
        NetworkActivityLevel.Listening => IsListening ? "监听" : "端点",
        _ => "空闲"
    };
}

public sealed class NetworkCollectionResult
{
    public IReadOnlyList<NetworkConnectionRecord> Connections { get; init; } = Array.Empty<NetworkConnectionRecord>();
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    public string? Error { get; init; }
    public DateTimeOffset CapturedUtc { get; init; }
    public int TcpCount { get; init; }
    public int UdpCount { get; init; }
    public int UnknownProcessCount { get; init; }
}
