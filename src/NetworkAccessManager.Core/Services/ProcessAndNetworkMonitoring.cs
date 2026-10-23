using System.Collections.Concurrent;
using System.Diagnostics;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Native;

namespace NetworkAccessManager.Core.Services;

public sealed class ProcessSnapshotService
{
    private readonly IAppLog _log;
    private readonly ServiceCatalog _serviceCatalog;
    private readonly SignatureVerifier _signatureVerifier;

    public ProcessSnapshotService(IAppLog? log = null, SignatureVerifier? signatureVerifier = null)
    {
        _log = log ?? NullAppLog.Instance;
        _serviceCatalog = new ServiceCatalog();
        _signatureVerifier = signatureVerifier ?? new SignatureVerifier(_log);
    }

    public ProcessCollectionResult Capture(string? ownExecutablePath = null)
    {
        var capturedAt = DateTimeOffset.UtcNow;
        var warnings = new List<string>();
        var working = new List<WorkingProcess>();
        var pathFailures = 0;

        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch (Exception ex)
        {
            _log.Error("Processes", "枚举进程失败", ex);
            return new ProcessCollectionResult
            {
                Error = $"无法枚举进程：{ex.Message}",
                Warnings = warnings,
                CapturedUtc = capturedAt
            };
        }

        foreach (var process in processes)
        {
            try
            {
                var pid = process.Id;
                string name;
                try
                {
                    name = pid switch
                    {
                        0 => "System Idle Process",
                        4 => "System",
                        _ => process.ProcessName
                    };
                }
                catch (Exception ex)
                {
                    name = $"PID {pid}";
                    warnings.Add($"无法读取 PID {pid} 的进程名称：{ex.Message}");
                }

                var pathOk = ProcessNative.TryGetImagePath(pid, out var path, out var pathError);
                if (!pathOk) pathFailures++;
                ProcessNative.TryEnrichBasicInfo(process, out var sessionId, out var startTimeUtc, out _);

                working.Add(new WorkingProcess
                {
                    Pid = pid,
                    Name = name,
                    Path = path,
                    PathError = pathError,
                    SessionId = sessionId,
                    StartTimeUtc = startTimeUtc
                });
            }
            catch (Exception ex)
            {
                _log.Warn("Processes", $"读取进程信息时跳过一项：{ex.Message}");
            }
            finally
            {
                process.Dispose();
            }
        }

        var services = _serviceCatalog.Get();
        if (!string.IsNullOrWhiteSpace(services.Error))
            warnings.Add($"Windows 服务枚举不完整：{services.Error}");
        if (pathFailures > 0)
            warnings.Add($"{pathFailures} 个进程的可执行文件路径无法读取（受保护进程或权限不足），表中显示为未知。");

        var uniquePaths = working
            .Select(p => p.Path)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Cast<string>()
            .ToArray();

        var signatures = new ConcurrentDictionary<string, DigitalSignatureInfo>(StringComparer.OrdinalIgnoreCase);
        var versionInfo = new ConcurrentDictionary<string, (string? Description, string? CompanyName, string? FileVersion, string? Error)>(StringComparer.OrdinalIgnoreCase);
        Parallel.ForEach(
            uniquePaths,
            new ParallelOptions { MaxDegreeOfParallelism = 4 },
            path =>
            {
                signatures[path] = _signatureVerifier.Verify(path);
                versionInfo[path] = ProcessNative.ReadVersionInfo(path);
            });

        var records = new List<ProcessRecord>(working.Count);
        var classifier = new SystemProcessClassifier(ownExecutablePath);
        foreach (var item in working)
        {
            var signature = item.Path is not null && signatures.TryGetValue(item.Path, out var sig)
                ? sig
                : DigitalSignatureInfo.Unknown(item.PathError ?? "没有路径");
            var version = item.Path is not null && versionInfo.TryGetValue(item.Path, out var vi)
                ? vi
                : (Description: (string?)null, CompanyName: (string?)null, FileVersion: (string?)null, Error: null);
            IReadOnlyList<ServiceInstance> processServices =
                services.ServicesByProcess.TryGetValue(item.Pid, out var found)
                    ? found
                    : Array.Empty<ServiceInstance>();

            var displayDescription = item.Pid switch
            {
                0 => "系统空闲进程",
                4 => "Windows 系统进程",
                _ => version.Description
            };

            var record = new ProcessRecord
            {
                Pid = item.Pid,
                Name = item.Name,
                ExecutablePath = item.Path,
                Description = displayDescription ?? item.Name,
                CompanyName = version.CompanyName,
                FileVersion = version.FileVersion,
                SessionId = item.SessionId,
                StartTimeUtc = item.StartTimeUtc,
                Services = processServices,
                Signature = signature,
                ModuleQueryError = item.PathError,
                FileMetadataError = version.Error,
                CapturedUtc = capturedAt
            };
            try
            {
                classifier.Apply(record);
            }
            catch (Exception ex)
            {
                record.Category = ProcessCategory.Unknown;
                record.Risk = RiskLevel.High;
                record.ClassificationEvidence = "分类时出现异常，标记为待确认";
                record.RiskSummary = "分类待确认";
                _log.Warn("Processes", $"进程分类失败 PID {record.Pid}：{ex.Message}");
            }
            records.Add(record);
        }

        return new ProcessCollectionResult
        {
            Processes = records
                .OrderByDescending(p => p.Category == ProcessCategory.UserApplication ? 0 : 1)
                .ThenBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToList(),
            Warnings = warnings,
            CapturedUtc = capturedAt
        };
    }

    private sealed class WorkingProcess
    {
        public int Pid { get; init; }
        public required string Name { get; init; }
        public string? Path { get; init; }
        public int SessionId { get; init; }
        public DateTimeOffset? StartTimeUtc { get; init; }
        public string? PathError { get; init; }
    }
}

public sealed class NetworkConnectionService
{
    private readonly IAppLog _log;

    public NetworkConnectionService(IAppLog? log = null)
    {
        _log = log ?? NullAppLog.Instance;
    }

    public NetworkCollectionResult Capture(IReadOnlyList<ProcessRecord> processes)
    {
        var capturedAt = DateTimeOffset.UtcNow;
        var warnings = new List<string>();
        var tcpRows = new List<RawTcpRow>();
        var udpRows = new List<RawUdpRow>();
        var failedSources = new List<string>();

        try { tcpRows.AddRange(NetworkTables.GetIpv4TcpRows()); }
        catch (Exception ex) { failedSources.Add("IPv4 TCP"); warnings.Add($"读取 IPv4 TCP 表失败：{ex.Message}"); }
        try { tcpRows.AddRange(NetworkTables.GetIpv6TcpRows()); }
        catch (Exception ex) { failedSources.Add("IPv6 TCP"); warnings.Add($"读取 IPv6 TCP 表失败：{ex.Message}"); }
        try { udpRows.AddRange(NetworkTables.GetIpv4UdpRows()); }
        catch (Exception ex) { failedSources.Add("IPv4 UDP"); warnings.Add($"读取 IPv4 UDP 表失败：{ex.Message}"); }
        try { udpRows.AddRange(NetworkTables.GetIpv6UdpRows()); }
        catch (Exception ex) { failedSources.Add("IPv6 UDP"); warnings.Add($"读取 IPv6 UDP 表失败：{ex.Message}"); }

        if (failedSources.Count == 4)
        {
            var error = "无法读取任何 TCP/UDP 网络表：" + string.Join("；", warnings);
            _log.Error("Network", error);
            return new NetworkCollectionResult
            {
                Error = error,
                Warnings = warnings,
                CapturedUtc = capturedAt
            };
        }

        var processMap = processes
            .GroupBy(p => p.Pid)
            .ToDictionary(g => g.Key, g => g.First());
        var connections = new List<NetworkConnectionRecord>(tcpRows.Count + udpRows.Count);
        var unknown = 0;

        foreach (var row in tcpRows)
        {
            processMap.TryGetValue(row.OwningPid, out var ownerProcess);
            var resolved = row.OwningPid > 0 && ownerProcess is not null;
            if (!resolved) unknown++;
            var remoteAddress = row.RemotePort > 0 ? row.RemoteAddress.ToString() : null;
            var isListen = row.State == 2;
            connections.Add(new NetworkConnectionRecord
            {
                ConnectionId = MakeId(NetworkProtocol.Tcp, row.AddressFamily, row.LocalAddress, row.LocalPort, remoteAddress, row.RemotePort, row.OwningPid),
                Protocol = NetworkProtocol.Tcp,
                IpVersion = row.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? IpVersion.IPv4 : IpVersion.IPv6,
                OwningPid = row.OwningPid,
                ProcessResolved = resolved,
                ProcessName = resolved ? ownerProcess!.Name : null,
                ProcessPath = resolved ? ownerProcess!.ExecutablePath : null,
                LocalAddress = row.LocalAddress.ToString(),
                LocalPort = row.LocalPort,
                RemoteAddress = remoteAddress,
                RemotePort = row.RemotePort > 0 ? row.RemotePort : null,
                TcpStateCode = row.State,
                TcpStateText = NetworkTables.TcpStateText(row.State),
                IsListening = isListen,
                ActivityLevel = isListen ? NetworkActivityLevel.Listening : NetworkActivityLevel.Active,
                CapturedUtc = capturedAt
            });
        }

        foreach (var row in udpRows)
        {
            processMap.TryGetValue(row.OwningPid, out var ownerProcess);
            var resolved = row.OwningPid > 0 && ownerProcess is not null;
            if (!resolved) unknown++;
            connections.Add(new NetworkConnectionRecord
            {
                ConnectionId = MakeId(NetworkProtocol.Udp, row.AddressFamily, row.LocalAddress, row.LocalPort, null, null, row.OwningPid),
                Protocol = NetworkProtocol.Udp,
                IpVersion = row.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? IpVersion.IPv4 : IpVersion.IPv6,
                OwningPid = row.OwningPid,
                ProcessResolved = resolved,
                ProcessName = resolved ? ownerProcess!.Name : null,
                ProcessPath = resolved ? ownerProcess!.ExecutablePath : null,
                LocalAddress = row.LocalAddress.ToString(),
                LocalPort = row.LocalPort,
                RemoteAddress = null,
                RemotePort = null,
                TcpStateCode = null,
                TcpStateText = "—",
                IsListening = true,
                ActivityLevel = NetworkActivityLevel.Listening,
                CapturedUtc = capturedAt
            });
        }

        return new NetworkCollectionResult
        {
            Connections = connections
                .OrderBy(c => c.ProcessName ?? "\uFFFF", StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(c => c.Protocol)
                .ThenBy(c => c.LocalPort)
                .ToList(),
            Warnings = warnings,
            Error = null,
            CapturedUtc = capturedAt,
            TcpCount = tcpRows.Count,
            UdpCount = udpRows.Count,
            UnknownProcessCount = unknown
        };
    }

    private static string MakeId(
        NetworkProtocol protocol,
        System.Net.Sockets.AddressFamily family,
        System.Net.IPAddress local,
        int localPort,
        string? remote,
        int? remotePort,
        int pid) =>
        $"{protocol}|{(family == System.Net.Sockets.AddressFamily.InterNetwork ? "4" : "6")}|{local}|{localPort}|{remote ?? "*"}|{remotePort?.ToString() ?? "*"}|{pid}";
}
