namespace NetworkAccessManager.Core.Models;

public sealed class ServiceInstance
{
    public string Name { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string State { get; init; } = string.Empty;
    public int ProcessId { get; init; }
}

public sealed class DigitalSignatureInfo
{
    public SignatureState State { get; set; } = SignatureState.Unknown;
    public string? Publisher { get; set; }
    public string StatusText { get; set; } = "未知";
    public bool IsMicrosoft { get; set; }
    public uint? TrustErrorCode { get; set; }
    public string? Error { get; set; }

    public static DigitalSignatureInfo Unknown(string reason = "尚未检查") => new()
    {
        State = SignatureState.Unknown,
        StatusText = $"未知（{reason}）"
    };
}

public sealed class ProcessRecord
{
    public int Pid { get; init; }
    public string Name { get; init; } = string.Empty;
    public string? ExecutablePath { get; init; }
    public string? Description { get; init; }
    public string? CompanyName { get; init; }
    public string? FileVersion { get; init; }
    public int SessionId { get; init; }
    public DateTimeOffset? StartTimeUtc { get; init; }
    public IReadOnlyList<ServiceInstance> Services { get; init; } = Array.Empty<ServiceInstance>();
    public DigitalSignatureInfo Signature { get; init; } = new();
    public ProcessCategory Category { get; set; } = ProcessCategory.Unknown;
    public RiskLevel Risk { get; set; } = RiskLevel.Normal;
    public string RiskSummary { get; set; } = "普通用户应用";
    public bool IsProgramBlockProtected { get; set; }
    public string ProtectionReason { get; set; } = string.Empty;
    public string ClassificationEvidence { get; set; } = string.Empty;
    public string? ModuleQueryError { get; init; }
    public string? FileMetadataError { get; init; }
    public DateTimeOffset CapturedUtc { get; init; }

    public string? NormalizedPath => string.IsNullOrWhiteSpace(ExecutablePath)
        ? null
        : ExecutablePath.Trim();

    public string DisplayName => string.IsNullOrWhiteSpace(Description) ? Name : Description!;

    public string CategoryText => Category switch
    {
        ProcessCategory.UserApplication => "用户应用",
        ProcessCategory.WindowsService => "服务进程",
        ProcessCategory.WindowsComponent => "Windows 组件",
        ProcessCategory.SystemCritical => "关键系统组件",
        _ => "分类待确认"
    };

    public string ServiceSummary
    {
        get
        {
            if (Services.Count == 0) return "—";
            if (Services.Count == 1) return Services[0].DisplayName;
            return $"{Services[0].DisplayName} 等 {Services.Count} 项服务";
        }
    }
}

public sealed class ProcessCollectionResult
{
    public IReadOnlyList<ProcessRecord> Processes { get; init; } = Array.Empty<ProcessRecord>();
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    public string? Error { get; init; }
    public DateTimeOffset CapturedUtc { get; init; }
}
