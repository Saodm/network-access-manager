using System.Collections.Concurrent;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Native;

namespace NetworkAccessManager.Core.Services;

public sealed class SignatureVerifier
{
    private sealed record CacheEntry(string FileKey, DigitalSignatureInfo Info);

    private readonly ConcurrentDictionary<string, CacheEntry> _cache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly IAppLog _log;

    public SignatureVerifier(IAppLog? log = null)
    {
        _log = log ?? NullAppLog.Instance;
    }

    public DigitalSignatureInfo Verify(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return DigitalSignatureInfo.Unknown("没有可执行文件路径");

        string full;
        try
        {
            full = Path.GetFullPath(filePath);
        }
        catch (Exception ex)
        {
            return new DigitalSignatureInfo
            {
                State = SignatureState.Unavailable,
                StatusText = $"无法检查（{ex.Message}）",
                Error = ex.Message
            };
        }

        string fileKey;
        try
        {
            var info = new FileInfo(full);
            if (!info.Exists)
            {
                return new DigitalSignatureInfo
                {
                    State = SignatureState.Unavailable,
                    StatusText = "无法检查（文件不存在）",
                    Error = "文件不存在。"
                };
            }
            fileKey = $"{info.Length}:{info.LastWriteTimeUtc.Ticks}";
        }
        catch (Exception ex)
        {
            return new DigitalSignatureInfo
            {
                State = SignatureState.Unavailable,
                StatusText = $"无法检查（{ex.Message}）",
                Error = ex.Message
            };
        }

        if (_cache.TryGetValue(full, out var cached) && cached.FileKey == fileKey)
            return cached.Info;

        DigitalSignatureInfo result;
        try
        {
            var (code, publisher) = SignatureNative.Verify(full);
            if (code == 0)
            {
                result = new DigitalSignatureInfo
                {
                    State = SignatureState.Valid,
                    Publisher = publisher,
                    IsMicrosoft = publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true,
                    StatusText = string.IsNullOrWhiteSpace(publisher)
                        ? "签名有效（发布者未知）"
                        : $"签名有效 · {publisher}"
                };
            }
            else if (code is 0x800B0100 or 0x800B0101)
            {
                result = new DigitalSignatureInfo
                {
                    State = SignatureState.NotSigned,
                    TrustErrorCode = code,
                    StatusText = "未发现嵌入签名（可能是目录签名或未签名）",
                    Error = $"WinVerifyTrust 0x{code:X8}"
                };
            }
            else
            {
                var message = code switch
                {
                    0x800B0109 => "签名链不受信任",
                    0x800B010A => "证书链无法建立",
                    0x800B010C => "证书已被吊销",
                    0x80096010 => "签名摘要不匹配（文件可能被修改）",
                    0x80096019 => "签名格式无效",
                    _ => "签名验证未通过"
                };
                result = new DigitalSignatureInfo
                {
                    State = SignatureState.Invalid,
                    TrustErrorCode = code,
                    StatusText = $"{message}（0x{code:X8}）",
                    Error = $"WinVerifyTrust 0x{code:X8}"
                };
            }
        }
        catch (Exception ex)
        {
            _log.Warn("Signature", $"验证签名失败：{full}：{ex.Message}");
            result = new DigitalSignatureInfo
            {
                State = SignatureState.Unavailable,
                StatusText = $"无法检查（{ex.Message}）",
                Error = ex.Message
            };
        }

        _cache[full] = new CacheEntry(fileKey, result);
        return result;
    }

    public void Clear() => _cache.Clear();
}

public sealed class ServiceCatalog
{
    private readonly object _gate = new();
    private ServiceEnumerationResult? _cached;
    private DateTimeOffset _cachedAt;
    private readonly TimeSpan _ttl = TimeSpan.FromSeconds(8);

    public ServiceEnumerationResult Get()
    {
        lock (_gate)
        {
            if (_cached is not null && DateTimeOffset.UtcNow - _cachedAt < _ttl)
                return _cached;
            _cached = ServiceNative.Enumerate();
            _cachedAt = DateTimeOffset.UtcNow;
            return _cached;
        }
    }
}

public sealed class SystemProcessClassifier
{
    private static readonly HashSet<string> CriticalBinaryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe"
    };

    private readonly string _windowsDirectory;
    private readonly string _system32Directory;
    private readonly string? _ownExecutable;

    public SystemProcessClassifier(string? ownExecutablePath = null)
    {
        _windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            .TrimEnd(Path.DirectorySeparatorChar);
        _system32Directory = Environment.SystemDirectory.TrimEnd(Path.DirectorySeparatorChar);
        _ownExecutable = ownExecutablePath;
    }

    public void Apply(ProcessRecord process)
    {
        var path = process.ExecutablePath;
        var fileName = string.IsNullOrWhiteSpace(path) ? process.Name : Path.GetFileName(path);
        var underWindows = IsUnderDirectory(path, _windowsDirectory);
        var underSystem32 = IsUnderDirectory(path, _system32Directory);
        var hasServices = process.Services.Count > 0;
        var sessionZero = process.SessionId == 0;
        var signatureValidMicrosoft = process.Signature.State == SignatureState.Valid && process.Signature.IsMicrosoft;
        var protectedByName = IsCriticalBinaryName(fileName);
        var criticalEvidence = protectedByName && (sessionZero || underWindows || hasServices);

        if (process.Pid is 0 or 4)
        {
            process.Category = ProcessCategory.SystemCritical;
            process.Risk = RiskLevel.Critical;
            process.IsProgramBlockProtected = true;
            process.ProtectionReason = process.Pid == 4
                ? "Windows 内核相关系统进程，不能按程序路径阻断。"
                : "系统空闲进程没有可执行的网络程序，不能建立程序规则。";
            process.RiskSummary = process.ProtectionReason;
            process.ClassificationEvidence = process.Pid == 4
                ? "系统进程 PID 4（由会话/系统信息识别）"
                : "系统空闲进程 PID 0";
            return;
        }

        if (criticalEvidence)
        {
            process.Category = ProcessCategory.SystemCritical;
            process.Risk = RiskLevel.Critical;
            process.IsProgramBlockProtected = true;
            process.ClassificationEvidence = BuildEvidence(sessionZero, hasServices, signatureValidMicrosoft, underWindows);
            var serviceDetail = hasServices
                ? $"该进程承载 {process.Services.Count} 个 Windows 服务（{string.Join("、", process.Services.Take(4).Select(s => s.DisplayName))}{(process.Services.Count > 4 ? "…" : string.Empty)}）。"
                : string.Empty;
            process.ProtectionReason = fileName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
                ? $"svchost.exe 可能同时承载多个 Windows 服务。{serviceDetail}按程序路径阻断会同时影响全部承载服务，本工具暂不允许直接操作。"
                : $"{fileName} 是关键系统组件。{serviceDetail}为保证系统启动、登录和网络安全，本工具不允许按程序阻断。";
            process.RiskSummary = "关键系统组件，按程序阻断已禁用";
            return;
        }

        if (hasServices)
        {
            process.Category = ProcessCategory.WindowsService;
            process.Risk = RiskLevel.High;
            process.ClassificationEvidence = BuildEvidence(sessionZero, true, signatureValidMicrosoft, underWindows);
            process.RiskSummary = $"承载 {process.Services.Count} 个 Windows 服务，阻断后可能影响依赖这些服务的系统功能";
            CheckOwnExecutable(process, path);
            return;
        }

        if (sessionZero || underSystem32)
        {
            process.Category = signatureValidMicrosoft ? ProcessCategory.WindowsComponent : ProcessCategory.Unknown;
            process.Risk = signatureValidMicrosoft ? RiskLevel.Caution : RiskLevel.High;
            process.ClassificationEvidence = underWindows && !signatureValidMicrosoft
                ? "位于 Windows 目录，但数字签名未能验证为受信任的 Microsoft 签名，分类待确认"
                : BuildEvidence(sessionZero, false, signatureValidMicrosoft, underWindows);
            process.RiskSummary = signatureValidMicrosoft
                ? "Windows 系统组件，阻断可能影响系统或安全功能"
                : "分类待确认：系统目录中的程序，签名/发布者无法可靠确认";
            CheckOwnExecutable(process, path);
            return;
        }

        if (underWindows)
        {
            process.Category = signatureValidMicrosoft ? ProcessCategory.WindowsComponent : ProcessCategory.Unknown;
            process.Risk = signatureValidMicrosoft ? RiskLevel.Caution : RiskLevel.High;
            process.ClassificationEvidence = signatureValidMicrosoft
                ? "位于 Windows 目录并具有受信任的 Microsoft 签名"
                : "位于 Windows 目录，但未验证为受信任的 Microsoft 签名，分类待确认";
            process.RiskSummary = signatureValidMicrosoft
                ? "Windows 组件，阻断可能影响系统功能"
                : "分类待确认：签名无法可靠确认";
            CheckOwnExecutable(process, path);
            return;
        }

        process.Category = ProcessCategory.UserApplication;
        process.Risk = RiskLevel.Normal;
        process.ClassificationEvidence = "用户会话中的普通程序";
        process.RiskSummary = "普通用户应用";
        CheckOwnExecutable(process, path);
    }

    private void CheckOwnExecutable(ProcessRecord process, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path) && !string.IsNullOrWhiteSpace(_ownExecutable))
        {
            try
            {
                if (string.Equals(Path.GetFullPath(path), Path.GetFullPath(_ownExecutable), StringComparison.OrdinalIgnoreCase))
                {
                    process.IsProgramBlockProtected = true;
                    process.Risk = RiskLevel.High;
                    process.ProtectionReason = "不能阻断本工具自身，否则后续无法执行解除、取消定时任务和恢复操作。";
                    process.RiskSummary = "本工具进程，按程序阻断已禁用";
                }
            }
            catch
            {
                // Path comparison failure does not grant extra privileges.
            }
        }
    }

    private static bool IsCriticalBinaryName(string fileName) =>
        CriticalBinaryNames.Contains(fileName);

    private static bool IsUnderDirectory(string? path, string directory)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(directory)) return false;
        try
        {
            var full = Path.GetFullPath(path);
            var root = directory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string BuildEvidence(bool sessionZero, bool hasServices, bool signedMicrosoft, bool underWindows)
    {
        var evidence = new List<string>();
        evidence.Add(sessionZero ? "会话 0（非交互/服务会话）" : "交互会话");
        if (hasServices) evidence.Add("承载 Windows 服务");
        if (underWindows) evidence.Add("位于 Windows 目录");
        evidence.Add(signedMicrosoft ? "Microsoft 有效签名" : "签名未验证为 Microsoft");
        return string.Join("；", evidence);
    }
}
