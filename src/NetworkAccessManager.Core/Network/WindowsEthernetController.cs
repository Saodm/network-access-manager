using System.Diagnostics;
using System.Text;
using System.Text.Json;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;

namespace NetworkAccessManager.Core.Network;

/// <summary>
/// Controls physical Ethernet adapters through the built-in Windows
/// NetAdapter cmdlets. The helper process is already elevated; this class does
/// not attempt to elevate or bypass UAC. All target identifiers are validated
/// GUIDs and are passed through environment variables, never concatenated into
/// a PowerShell command line.
/// </summary>
public sealed class WindowsEthernetController : IEthernetController
{
    private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(45);
    private const string OperationEnvironment = "NAM_ETHERNET_OP";
    private const string IdsEnvironment = "NAM_ETHERNET_IDS";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public IReadOnlyList<EthernetAdapterInfo> Inspect()
    {
        var result = RunBridge("inspect", Array.Empty<string>());
        if (!result.Ok)
            throw new EthernetControlException(result.Error ?? "读取以太网适配器失败。");
        return result.After ?? result.Before ?? Array.Empty<EthernetAdapterInfo>();
    }

    public EthernetChangeResult Disable(IReadOnlyList<EthernetAdapterRecord> adapters)
    {
        var ids = NormalizeIds(adapters);
        if (ids.Count == 0)
            return new EthernetChangeResult { Success = false, Message = "没有要禁用的以太网适配器记录。" };

        var result = RunBridge("disable", ids);
        return Evaluate(result, ids, expectedEnabled: false);
    }

    public EthernetChangeResult Enable(IReadOnlyList<EthernetAdapterRecord> adapters)
    {
        var ids = NormalizeIds(adapters);
        if (ids.Count == 0)
            return new EthernetChangeResult { Success = false, Message = "没有要恢复的以太网适配器记录。" };

        var result = RunBridge("enable", ids);
        return Evaluate(result, ids, expectedEnabled: true);
    }

    private static EthernetChangeResult Evaluate(
        BridgeResult result,
        IReadOnlyList<string> requestedIds,
        bool expectedEnabled)
    {
        var after = result.After ?? Array.Empty<EthernetAdapterInfo>();
        var changed = new List<string>();
        var failed = new List<string>();
        foreach (var id in requestedIds)
        {
            var adapter = after.FirstOrDefault(a =>
                string.Equals(a.Id, id, StringComparison.OrdinalIgnoreCase));
            if (adapter is null)
            {
                failed.Add(id);
                continue;
            }
            if (adapter.AdminEnabled == expectedEnabled) changed.Add(id);
            else failed.Add(id);
        }

        var ok = result.Ok && failed.Count == 0;
        var message = result.Ok
            ? ok
                ? expectedEnabled
                    ? $"已恢复 {changed.Count} 个以太网适配器。"
                    : $"已禁用 {changed.Count} 个以太网适配器。"
                : $"操作未全部完成：成功 {changed.Count} 个，未确认/失败 {failed.Count} 个。"
            : $"Windows 未完成网络适配器操作：{result.Error ?? "未知错误"}";
        return new EthernetChangeResult
        {
            Success = ok,
            Message = message,
            ChangedAdapterIds = changed,
            FailedAdapterIds = failed,
            Before = result.Before ?? Array.Empty<EthernetAdapterInfo>(),
            After = after
        };
    }

    private static IReadOnlyList<string> NormalizeIds(IEnumerable<EthernetAdapterRecord> adapters) =>
        adapters
            .Select(a => EthernetAdapterInspector.NormalizeId(a.Id))
            .Where(id => Guid.TryParse(id, out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static BridgeResult RunBridge(string operation, IReadOnlyList<string> ids)
    {
        if (!WindowsPrivilege.IsAdministrator())
            return BridgeResult.Failure("该操作需要管理员权限。");

        var script = BuildScript();
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var powershell = Path.Combine(
            Environment.SystemDirectory,
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        if (!File.Exists(powershell))
            return BridgeResult.Failure("找不到 Windows PowerShell。");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = powershell,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = AppContext.BaseDirectory
            };
            psi.ArgumentList.Add("-NoLogo");
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-EncodedCommand");
            psi.ArgumentList.Add(encoded);
            psi.Environment[OperationEnvironment] = operation;
            psi.Environment[IdsEnvironment] = string.Join(';', ids);

            using var process = Process.Start(psi);
            if (process is null)
                return BridgeResult.Failure("无法启动 Windows 网络适配器控制器。");

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(OperationTimeout))
            {
                try { process.Kill(true); } catch { }
                return BridgeResult.Failure("网络适配器操作超时。");
            }

            var output = outputTask.GetAwaiter().GetResult();
            var error = errorTask.GetAwaiter().GetResult();
            var json = ExtractJson(output);
            if (json is null)
            {
                var detail = string.IsNullOrWhiteSpace(error) ? output.Trim() : error.Trim();
                return BridgeResult.Failure(string.IsNullOrWhiteSpace(detail)
                    ? "Windows 没有返回可解析的适配器结果。"
                    : detail);
            }

            var envelope = JsonSerializer.Deserialize<Envelope>(json, JsonOptions);
            if (envelope is null)
                return BridgeResult.Failure("Windows 适配器结果格式无效。");
            return new BridgeResult
            {
                Ok = envelope.Ok && process.ExitCode == 0,
                Error = envelope.Error,
                Before = envelope.Before?.Select(Map).ToList(),
                After = envelope.After?.Select(Map).ToList()
            };
        }
        catch (Exception ex)
        {
            return BridgeResult.Failure($"网络适配器操作失败：{ex.Message}");
        }
    }

    private static string? ExtractJson(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;
        var text = output.Trim().TrimStart('\uFEFF');
        var start = text.IndexOf('{');
        var end = text.LastIndexOf('}');
        if (start < 0 || end <= start) return null;
        return text[start..(end + 1)];
    }

    private static EthernetAdapterInfo Map(BridgeAdapter adapter)
    {
        bool? admin = string.Equals(adapter.AdminStatus, "Up", StringComparison.OrdinalIgnoreCase)
            ? true
            : string.IsNullOrWhiteSpace(adapter.AdminStatus) ? null : false;
        return new EthernetAdapterInfo
        {
            Id = EthernetAdapterInspector.NormalizeId(adapter.InterfaceGuid),
            Name = adapter.Name ?? adapter.InterfaceDescription ?? "以太网适配器",
            Description = adapter.InterfaceDescription ?? string.Empty,
            StatusText = adapter.Status switch
            {
                "Up" => "已连接",
                "Disconnected" => "未连接",
                "Disabled" => "已禁用",
                _ => adapter.Status ?? "未知"
            },
            MacAddress = adapter.MacAddress,
            AdminEnabled = admin
        };
    }

    private static string BuildScript() => """
        [Console]::OutputEncoding=[System.Text.Encoding]::UTF8
        $ProgressPreference='SilentlyContinue'
        $ErrorActionPreference='Stop'
        $op=$env:NAM_ETHERNET_OP
        $rawIds=@()
        if($env:NAM_ETHERNET_IDS){$rawIds=@($env:NAM_ETHERNET_IDS.Split(';',[System.StringSplitOptions]::RemoveEmptyEntries))}
        function Normalize-Id([string]$value){ return ([string]$value).Trim().Trim([char[]]@('{','}')).ToUpperInvariant() }
        $ids=@($rawIds | ForEach-Object { Normalize-Id $_ })
        function Get-Eth {
          @(Get-NetAdapter -Physical -IncludeHidden -ErrorAction Stop |
            Where-Object { $_.MediaType -eq '802.3' } |
            Select-Object Name,InterfaceDescription,InterfaceGuid,Status,
              @{Name='AdminStatus';Expression={ $_.AdminStatus.ToString() }},
              MediaType,MacAddress,ifIndex)
        }
        try {
          $before=@(Get-Eth)
          $liveTargets=@(Get-NetAdapter -Physical -IncludeHidden -ErrorAction Stop |
            Where-Object { $_.MediaType -eq '802.3' -and $ids -contains (Normalize-Id $_.InterfaceGuid) })
          if($op -eq 'disable'){
            $targets=@($liveTargets | Where-Object { $_.AdminStatus -eq 'Up' })
            foreach($target in $targets){ Disable-NetAdapter -InputObject $target -Confirm:$false -ErrorAction Stop }
            $deadline=(Get-Date).AddSeconds(15)
            do {
              Start-Sleep -Milliseconds 500
              $live=@(Get-Eth)
              $still=@($ids | Where-Object {
                $id=$_
                $row=$live | Where-Object { (Normalize-Id $_.InterfaceGuid) -eq $id } | Select-Object -First 1
                $row -and $row.AdminStatus -eq 'Up'
              })
            } while($still.Count -gt 0 -and (Get-Date) -lt $deadline)
          } elseif($op -eq 'enable'){
            foreach($target in $liveTargets){ Enable-NetAdapter -InputObject $target -Confirm:$false -ErrorAction Stop }
            $deadline=(Get-Date).AddSeconds(15)
            do {
              Start-Sleep -Milliseconds 500
              $live=@(Get-Eth)
              $waiting=@($ids | Where-Object {
                $id=$_
                $row=$live | Where-Object { (Normalize-Id $_.InterfaceGuid) -eq $id } | Select-Object -First 1
                -not $row -or $row.AdminStatus -ne 'Up'
              })
            } while($waiting.Count -gt 0 -and (Get-Date) -lt $deadline)
          }
          $after=@(Get-Eth)
          [pscustomobject]@{ ok=$true; op=$op; error=$null; before=$before; after=$after } | ConvertTo-Json -Depth 6 -Compress
        } catch {
          $after=@()
          try { $after=@(Get-Eth) } catch {}
          [pscustomobject]@{ ok=$false; op=$op; error=$_.Exception.Message; before=@(); after=$after } | ConvertTo-Json -Depth 6 -Compress
          exit 1
        }
        """;

    private sealed class Envelope
    {
        public bool Ok { get; set; }
        public string? Op { get; set; }
        public string? Error { get; set; }
        public List<BridgeAdapter>? Before { get; set; }
        public List<BridgeAdapter>? After { get; set; }
    }

    private sealed class BridgeAdapter
    {
        public string? Name { get; set; }
        public string? InterfaceDescription { get; set; }
        public string? InterfaceGuid { get; set; }
        public string? Status { get; set; }
        public string? AdminStatus { get; set; }
        public string? MediaType { get; set; }
        public string? MacAddress { get; set; }
        public int? IfIndex { get; set; }
    }

    private sealed class BridgeResult
    {
        public bool Ok { get; init; }
        public string? Error { get; init; }
        public IReadOnlyList<EthernetAdapterInfo>? Before { get; init; }
        public IReadOnlyList<EthernetAdapterInfo>? After { get; init; }

        public static BridgeResult Failure(string message) => new() { Ok = false, Error = message };
    }
}

public sealed class EthernetControlException : Exception
{
    public EthernetControlException(string message) : base(message) { }
}
