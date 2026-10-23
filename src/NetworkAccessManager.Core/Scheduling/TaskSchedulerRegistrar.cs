using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;

namespace NetworkAccessManager.Core.Scheduling;

public static partial class TaskNamePolicy
{
    public const string Prefix = "NAM_Task_";

    [GeneratedRegex(@"^NAM_Task_[0-9a-fA-F]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ValidTaskNameRegex();

    public static string ForTask(string taskId)
    {
        if (!Guid.TryParseExact(taskId, "N", out var guid))
            throw new ArgumentException("任务 ID 格式无效。", nameof(taskId));
        return Prefix + guid.ToString("N");
    }

    public static bool IsValid(string? name) =>
        !string.IsNullOrWhiteSpace(name) && ValidTaskNameRegex().IsMatch(name);
}

public static class ScheduledTaskXml
{
    private const string TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static string Build(
        string taskName,
        string executablePath,
        string taskId,
        DateTimeOffset runAtUtc,
        string description)
    {
        if (!TaskNamePolicy.IsValid(taskName))
            throw new ArgumentException("系统计划任务名称不符合本工具的命名规则。", nameof(taskName));
        if (!Path.IsPathFullyQualified(executablePath))
            throw new ArgumentException("计划任务程序路径必须是绝对路径。", nameof(executablePath));
        if (!Guid.TryParseExact(taskId, "N", out _))
            throw new ArgumentException("任务 ID 格式无效。", nameof(taskId));

        var sid = WindowsPrivilege.CurrentUserSid();
        if (string.IsNullOrWhiteSpace(sid))
            throw new InvalidOperationException("无法取得当前用户 SID，不能注册计划任务。");

        var localRunAt = runAtUtc.ToLocalTime().ToString("yyyy-MM-dd'T'HH:mm:ss");
        var settings = new XmlWriterSettings
        {
            Indent = true,
            Encoding = Encoding.Unicode,
            OmitXmlDeclaration = false
        };

        var builder = new StringBuilder();
        using (var writer = XmlWriter.Create(builder, settings))
        {
            writer.WriteStartDocument();
            writer.WriteStartElement("Task", TaskNamespace);
            writer.WriteAttributeString("version", "1.4");

            writer.WriteStartElement("RegistrationInfo");
            writer.WriteElementString("Date", DateTimeOffset.Now.ToString("O"));
            writer.WriteElementString("Author", "Network Access Manager");
            writer.WriteElementString("Description", description);
            writer.WriteEndElement();

            writer.WriteStartElement("Triggers");
            writer.WriteStartElement("TimeTrigger");
            writer.WriteElementString("StartBoundary", localRunAt);
            writer.WriteElementString("Enabled", "true");
            writer.WriteEndElement();
            writer.WriteEndElement();

            writer.WriteStartElement("Principals");
            writer.WriteStartElement("Principal");
            writer.WriteAttributeString("id", "Author");
            writer.WriteElementString("UserId", sid);
            writer.WriteElementString("LogonType", "InteractiveToken");
            writer.WriteElementString("RunLevel", "HighestAvailable");
            writer.WriteEndElement();
            writer.WriteEndElement();

            writer.WriteStartElement("Settings");
            writer.WriteElementString("MultipleInstancesPolicy", "IgnoreNew");
            writer.WriteElementString("DisallowStartIfOnBatteries", "false");
            writer.WriteElementString("StopIfGoingOnBatteries", "false");
            writer.WriteElementString("AllowHardTerminate", "true");
            writer.WriteElementString("StartWhenAvailable", "true");
            writer.WriteElementString("RunOnlyIfNetworkAvailable", "false");
            writer.WriteStartElement("IdleSettings");
            writer.WriteElementString("StopOnIdleEnd", "false");
            writer.WriteElementString("RestartOnIdle", "false");
            writer.WriteEndElement();
            writer.WriteElementString("AllowStartOnDemand", "true");
            writer.WriteElementString("Enabled", "true");
            writer.WriteElementString("Hidden", "false");
            writer.WriteElementString("RunOnlyIfIdle", "false");
            writer.WriteElementString("WakeToRun", "false");
            writer.WriteElementString("ExecutionTimeLimit", "PT10M");
            writer.WriteElementString("Priority", "7");
            writer.WriteEndElement();

            writer.WriteStartElement("Actions");
            writer.WriteAttributeString("Context", "Author");
            writer.WriteStartElement("Exec");
            writer.WriteElementString("Command", executablePath);
            writer.WriteElementString("Arguments", $"--execute-task={taskId}");
            writer.WriteEndElement();
            writer.WriteEndElement();

            writer.WriteEndElement();
            writer.WriteEndDocument();
        }

        return builder.ToString();
    }
}

/// <summary>
/// Registers exactly one one-shot task per scheduled operation. All command
/// arguments are passed via ArgumentList, never concatenated into a shell
/// command line. The app executable path is embedded as an XML element, not as
/// a shell command.
/// </summary>
public sealed class TaskSchedulerRegistrar : IScheduledTaskRegistrar
{
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(30);
    private readonly AppPaths _paths;
    private readonly IAppLog _log;
    private readonly string _executablePath;

    public TaskSchedulerRegistrar(AppPaths paths, string executablePath, IAppLog? log = null)
    {
        _paths = paths;
        _executablePath = executablePath;
        _log = log ?? NullAppLog.Instance;
    }

    public async Task RegisterAsync(
        string taskName,
        string arguments,
        DateTimeOffset runAtUtc,
        string description,
        CancellationToken cancellationToken = default)
    {
        if (!TaskNamePolicy.IsValid(taskName))
            throw new ScheduledTaskException("系统计划任务名称无效，未注册。");
        if (!Path.IsPathFullyQualified(_executablePath) || !File.Exists(_executablePath))
            throw new ScheduledTaskException($"计划任务程序路径不存在：{_executablePath}");
        if (!arguments.StartsWith("--execute-task=", StringComparison.Ordinal))
            throw new ScheduledTaskException("计划任务参数不允许使用未经校验的内容。");

        var taskId = arguments["--execute-task=".Length..].Trim();
        if (!Guid.TryParseExact(taskId, "N", out _))
            throw new ScheduledTaskException("计划任务参数中的任务 ID 无效。");

        _paths.EnsureDirectories();
        var xmlPath = Path.Combine(_paths.TempDirectory, $"task-{Guid.NewGuid():N}.xml");
        try
        {
            var xml = ScheduledTaskXml.Build(taskName, _executablePath, taskId, runAtUtc, description);
            await File.WriteAllTextAsync(xmlPath, xml, Encoding.Unicode, cancellationToken).ConfigureAwait(false);

            var result = await RunSchtasksAsync(
                ["/Create", "/TN", taskName, "/XML", xmlPath, "/F"],
                cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 0)
                throw new ScheduledTaskException($"注册 Windows 计划任务失败（退出码 {result.ExitCode}）：{FormatOutput(result)}");

            var query = await QueryAsync(taskName, cancellationToken).ConfigureAwait(false);
            if (!query.Exists)
            {
                try { await DeleteUnconditionallyAsync(taskName, cancellationToken).ConfigureAwait(false); } catch { }
                throw new ScheduledTaskException($"计划任务注册后无法验证其存在：{query.Error ?? "任务未找到"}");
            }

            _log.Info("Scheduler", $"已注册计划任务 {taskName}，计划执行（本地）：{runAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}");
        }
        catch
        {
            try
            {
                _ = await RunSchtasksAsync(["/Delete", "/TN", taskName, "/F"], cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Best effort cleanup of a partially registered task.
            }
            throw;
        }
        finally
        {
            try { if (File.Exists(xmlPath)) File.Delete(xmlPath); } catch { }
        }
    }

    public async Task<bool> ExistsAsync(string taskName, CancellationToken cancellationToken = default)
    {
        var query = await QueryAsync(taskName, cancellationToken).ConfigureAwait(false);
        return query.Exists;
    }

    public async Task DeleteAsync(string taskName, CancellationToken cancellationToken = default)
    {
        if (!TaskNamePolicy.IsValid(taskName))
            throw new ScheduledTaskException("拒绝操作非本工具命名规则的计划任务。");

        var before = await QueryAsync(taskName, cancellationToken).ConfigureAwait(false);
        if (!before.Exists)
        {
            if (!before.Accessible)
                throw new ScheduledTaskException($"无法确认计划任务状态，取消未完成：{before.Error}");
            return;
        }

        var result = await RunSchtasksAsync(["/Delete", "/TN", taskName, "/F"], cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
            throw new ScheduledTaskException($"删除 Windows 计划任务失败（退出码 {result.ExitCode}）：{FormatOutput(result)}");

        var after = await QueryAsync(taskName, cancellationToken).ConfigureAwait(false);
        if (after.Exists)
            throw new ScheduledTaskException("Windows 计划任务删除后仍然存在，取消失败。");
        if (!after.Accessible)
            throw new ScheduledTaskException($"无法验证计划任务已删除：{after.Error}");
    }

    public async Task<ScheduledTaskQueryResult> QueryAsync(string taskName, CancellationToken cancellationToken = default)
    {
        if (!TaskNamePolicy.IsValid(taskName))
            return new ScheduledTaskQueryResult { Exists = false, Accessible = true, Error = "任务名称不符合本工具命名规则。" };

        try
        {
            var result = await RunSchtasksAsync(
                ["/Query", "/TN", taskName, "/XML"],
                cancellationToken).ConfigureAwait(false);
            if (result.ExitCode == 0)
                return new ScheduledTaskQueryResult { Exists = true, Accessible = true, Detail = "任务存在。" };

            var output = FormatOutput(result);
            var accessDenied = output.Contains("拒绝访问", StringComparison.OrdinalIgnoreCase) ||
                               output.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) ||
                               output.Contains("Access denied", StringComparison.OrdinalIgnoreCase);
            return new ScheduledTaskQueryResult
            {
                Exists = false,
                Accessible = !accessDenied,
                Error = output,
                Detail = accessDenied ? "访问计划任务被拒绝。" : "计划任务不存在。"
            };
        }
        catch (Exception ex)
        {
            return new ScheduledTaskQueryResult { Exists = false, Accessible = false, Error = ex.Message };
        }
    }

    private async Task DeleteUnconditionallyAsync(string taskName, CancellationToken cancellationToken)
    {
        if (!TaskNamePolicy.IsValid(taskName)) return;
        await RunSchtasksAsync(["/Delete", "/TN", taskName, "/F"], cancellationToken).ConfigureAwait(false);
    }

    private async Task<ProcessResult> RunSchtasksAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        var schtasks = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        if (!File.Exists(schtasks))
            throw new ScheduledTaskException("找不到系统计划任务程序 schtasks.exe。");

        var psi = new ProcessStartInfo
        {
            FileName = schtasks,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = psi };
        if (!process.Start())
            throw new ScheduledTaskException("无法启动系统计划任务程序。");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = new CancellationTokenSource(ProcessTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new ScheduledTaskException(timeout.IsCancellationRequested
                ? "调用系统计划任务程序超时（30 秒）。"
                : "计划任务操作已取消。");
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        _log.Info("Scheduler", $"schtasks {string.Join(' ', arguments)} -> {process.ExitCode}");
        return new ProcessResult(process.ExitCode, stdout, stderr);
    }

    private static string FormatOutput(ProcessResult result)
    {
        var text = string.Join(" ", new[] { result.StdOut, result.StdErr }
            .Where(s => !string.IsNullOrWhiteSpace(s)))
            .ReplaceLineEndings(" ")
            .Trim();
        if (text.Length > 900) text = text[..900] + "…";
        return text;
    }

    private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
}
