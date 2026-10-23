using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Services;

namespace NetworkAccessManager.Tests;

public sealed class SystemProcessClassifierTests
{
    private static ProcessRecord Create(
        int pid,
        string name,
        string? path,
        int sessionId,
        int services = 0,
        SignatureState signatureState = SignatureState.NotSigned,
        bool microsoft = false,
        string? ownPath = null)
    {
        var record = new ProcessRecord
        {
            Pid = pid,
            Name = name,
            ExecutablePath = path,
            SessionId = sessionId,
            Signature = new DigitalSignatureInfo
            {
                State = signatureState,
                IsMicrosoft = microsoft,
                StatusText = signatureState.ToString()
            },
            Services = Enumerable.Range(1, services).Select(i => new ServiceInstance
            {
                Name = $"Service{i}",
                DisplayName = $"服务 {i}",
                State = "RUNNING",
                ProcessId = pid
            }).ToList()
        };
        new SystemProcessClassifier(ownPath).Apply(record);
        return record;
    }

    [Fact]
    public void Svchost_with_system_evidence_is_protected()
    {
        var system32 = Environment.SystemDirectory;
        var record = Create(100, "svchost.exe", Path.Combine(system32, "svchost.exe"), 0, services: 8,
            signatureState: SignatureState.Valid, microsoft: true);
        Assert.Equal(ProcessCategory.SystemCritical, record.Category);
        Assert.True(record.IsProgramBlockProtected);
        Assert.Contains("多个", record.ProtectionReason);
        Assert.Equal(RiskLevel.Critical, record.Risk);
    }

    [Fact]
    public void Process_name_alone_does_not_protect()
    {
        using var workspace = new TempWorkspace();
        var fake = Path.Combine(workspace.Root, "svchost.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "where.exe"), fake);
        var record = Create(200, "svchost.exe", fake, 1, services: 0,
            signatureState: SignatureState.NotSigned, microsoft: false);
        Assert.Equal(ProcessCategory.UserApplication, record.Category);
        Assert.False(record.IsProgramBlockProtected);
    }

    [Fact]
    public void Microsoft_signed_windows_component_is_classified()
    {
        var system32 = Environment.SystemDirectory;
        var record = Create(300, "notepad.exe", Path.Combine(system32, "notepad.exe"), 1,
            signatureState: SignatureState.Valid, microsoft: true);
        Assert.Equal(ProcessCategory.WindowsComponent, record.Category);
        Assert.False(record.IsProgramBlockProtected);
        Assert.Equal(RiskLevel.Caution, record.Risk);
    }

    [Fact]
    public void Windows_directory_with_untrusted_signature_is_unknown_and_high_risk()
    {
        var system32 = Environment.SystemDirectory;
        var record = Create(301, "suspicious.exe", Path.Combine(system32, "suspicious.exe"), 1,
            signatureState: SignatureState.Invalid, microsoft: false);
        Assert.Equal(ProcessCategory.Unknown, record.Category);
        Assert.Equal(RiskLevel.High, record.Risk);
        Assert.Contains("分类待确认", record.RiskSummary);
    }

    [Fact]
    public void Service_process_is_classified_and_high_risk()
    {
        using var workspace = new TempWorkspace();
        var serviceExe = Path.Combine(workspace.Root, "service.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "where.exe"), serviceExe);
        var record = Create(400, "service.exe", serviceExe, 0, services: 2);
        Assert.Equal(ProcessCategory.WindowsService, record.Category);
        Assert.Equal(RiskLevel.High, record.Risk);
        Assert.False(record.IsProgramBlockProtected);
    }

    [Fact]
    public void Own_executable_is_protected()
    {
        using var workspace = new TempWorkspace();
        var record = Create(500, "TestNetworkApp.exe", workspace.DummyExePath, 1, ownPath: workspace.DummyExePath);
        Assert.True(record.IsProgramBlockProtected);
        Assert.Contains("本工具自身", record.ProtectionReason);
    }

    [Fact]
    public void System_pid_is_protected()
    {
        var record = Create(4, "System", null, 0);
        Assert.Equal(ProcessCategory.SystemCritical, record.Category);
        Assert.True(record.IsProgramBlockProtected);
    }
}
