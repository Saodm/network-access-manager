using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Firewall;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Scheduling;
using NetworkAccessManager.Core.Security;

namespace NetworkAccessManager.Core.Operations;

public sealed class ElevationInvocationResult
{
    public bool Started { get; init; }
    public bool UserCancelled { get; init; }
    public bool TimedOut { get; init; }
    public ElevatedResponse? Response { get; init; }
    public string? Error { get; init; }
    public int? ProcessExitCode { get; init; }
}

/// <summary>
/// Launches the same executable in helper mode through the normal Windows UAC
/// shell verb. There is no saved password, bypass or service-based back door.
/// The helper receives only a base64url JSON request and writes a result file.
/// </summary>
public sealed class ElevationClient
{
    private readonly AppPaths _paths;
    private readonly string _executablePath;
    private readonly IAppLog _log;

    public ElevationClient(AppPaths paths, string executablePath, IAppLog? log = null)
    {
        _paths = paths;
        _executablePath = executablePath;
        _log = log ?? NullAppLog.Instance;
    }

    public async Task<ElevationInvocationResult> InvokeAsync(
        ElevatedRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.Actions.Count == 0)
            return new ElevationInvocationResult { Started = false, Error = "没有要执行的操作。" };
        if (request.Actions.Count > NetworkControlService.MaxActionsPerRequest)
            return new ElevationInvocationResult { Started = false, Error = $"一次最多处理 {NetworkControlService.MaxActionsPerRequest} 个操作项。" };
        if (!Guid.TryParseExact(request.RequestId, "N", out _))
            return new ElevationInvocationResult { Started = false, Error = "请求 ID 无效。" };
        if (!File.Exists(_executablePath))
            return new ElevationInvocationResult { Started = false, Error = "找不到本程序可执行文件。" };

        request.UserSid = WindowsPrivilege.CurrentUserSid();
        request.CreatedUtc = DateTimeOffset.UtcNow;
        var encoded = HelperRequestCodec.Encode(request);
        if (encoded.Length > 28_000)
            return new ElevationInvocationResult
            {
                Started = false,
                Error = "本次批量操作的数据过大。请减少一次选择的数量后重试。"
            };

        var resultPath = _paths.ResultFilePath(request.RequestId);
        try
        {
            _paths.EnsureDirectories();
            if (File.Exists(resultPath)) File.Delete(resultPath);
        }
        catch (Exception ex)
        {
            return new ElevationInvocationResult { Started = false, Error = $"无法准备结果文件：{ex.Message}" };
        }

        Process? process = null;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = _executablePath,
                Arguments = $"{HelperProtocol.ElevatedRequestArgument}{encoded}",
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            process = Process.Start(psi);
            if (process is null)
                return new ElevationInvocationResult { Started = false, Error = "未能启动管理员授权进程。" };
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            _log.Warn("Elevation", "用户取消了 UAC 管理员授权。");
            return new ElevationInvocationResult
            {
                Started = false,
                UserCancelled = true,
                Error = "管理员授权被取消。没有创建或修改任何规则。"
            };
        }
        catch (Exception ex)
        {
            _log.Error("Elevation", "启动提权辅助进程失败", ex);
            return new ElevationInvocationResult { Started = false, Error = $"无法启动管理员授权进程：{ex.Message}" };
        }

        var deadline = DateTime.UtcNow.AddMinutes(4);
        try
        {
            while (DateTime.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var response = HelperRequestCodec.TryReadResult(_paths, request.RequestId);
                if (response is not null)
                {
                    try
                    {
                        await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
                    }
                    catch
                    {
                        // The response file is authoritative even if the process
                        // is still exiting. Do not kill an elevated helper.
                    }
                    return new ElevationInvocationResult
                    {
                        Started = true,
                        Response = response,
                        ProcessExitCode = process.HasExited ? process.ExitCode : null
                    };
                }

                if (process.HasExited)
                {
                    // Give the file write a moment to land even if process exit
                    // raced with the result read.
                    await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                    response = HelperRequestCodec.TryReadResult(_paths, request.RequestId);
                    if (response is not null)
                    {
                        return new ElevationInvocationResult
                        {
                            Started = true,
                            Response = response,
                            ProcessExitCode = process.ExitCode
                        };
                    }
                    _log.Error("Elevation", $"提权辅助进程退出（{process.ExitCode}），但没有返回结果文件。");
                    return new ElevationInvocationResult
                    {
                        Started = true,
                        Error = $"管理员辅助进程退出（退出码 {process.ExitCode}），但没有返回可验证的操作结果。请刷新后检查防火墙与历史记录，不要假定操作成功。",
                        ProcessExitCode = process.ExitCode
                    };
                }

                await Task.Delay(250, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            return new ElevationInvocationResult
            {
                Started = true,
                Error = "已停止等待管理员操作结果。辅助进程可能仍在运行；请刷新状态后再做判断。"
            };
        }
        finally
        {
            process.Dispose();
        }

        return new ElevationInvocationResult
        {
            Started = true,
            TimedOut = true,
            Error = "等待管理员操作结果超时。辅助进程可能仍在执行；请刷新后再判断，切勿直接假定成功。"
        };
    }
}

public sealed class HelperHost
{
    private readonly AppPaths _paths;
    private readonly IAppLog _log;
    private readonly string _executablePath;

    public HelperHost(AppPaths paths, string executablePath, IAppLog log)
    {
        _paths = paths;
        _executablePath = executablePath;
        _log = log;
    }

    public async Task<int> RunElevatedRequestAsync(
        string encodedRequest,
        CancellationToken cancellationToken = default,
        string source = "UAC 辅助进程")
    {
        ElevatedRequest request;
        try
        {
            request = HelperRequestCodec.Decode(encodedRequest);
        }
        catch (Exception ex)
        {
            _log.Error("Helper", "无法解码提权请求", ex);
            return 2;
        }

        var started = DateTimeOffset.UtcNow;
        var response = new ElevatedResponse
        {
            RequestId = request.RequestId,
            StartedUtc = started
        };

        var exitCode = 0;
        try
        {
            if (!Guid.TryParseExact(request.RequestId, "N", out _))
                throw new InvalidOperationException("请求 ID 无效。");
            if (request.ProtocolVersion != 1)
                throw new InvalidOperationException($"不支持的请求协议版本 {request.ProtocolVersion}。");
            if (!string.Equals(request.UserSid, WindowsPrivilege.CurrentUserSid(), StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("当前提权进程的用户身份与发起请求的用户不一致，已拒绝执行。");
            if (!WindowsPrivilege.IsAdministrator())
                throw new UnauthorizedAccessException(
                    "没有得到管理员权限，已拒绝执行。当前辅助进程没有被 Windows 提升为管理员。请先完全关闭本工具的所有窗口，再右键 NetworkAccessManager.exe 选择“以管理员身份运行”；启动后顶部应显示“已取得管理员权限”。若没有出现 UAC 提示，请检查 Windows UAC 设置或安全软件。未修改任何规则。");
            if (request.Actions.Count == 0)
                throw new InvalidOperationException("请求中没有操作项。");
            if (request.Actions.Count > NetworkControlService.MaxActionsPerRequest)
                throw new InvalidOperationException($"单次请求最多包含 {NetworkControlService.MaxActionsPerRequest} 个操作项。");
            if (request.Actions.Select(a => a.ActionId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != request.Actions.Count)
                throw new InvalidOperationException("请求中存在重复的操作项 ID。");
            if (request.CreatedUtc > DateTimeOffset.UtcNow.AddMinutes(5) ||
                request.CreatedUtc < DateTimeOffset.UtcNow.AddHours(-24))
                throw new InvalidOperationException("请求时间超出可接受范围。");

            var store = new StateRepository(_paths);
            var firewall = new ComFirewallManager();
            var scheduler = new TaskSchedulerRegistrar(_paths, _executablePath, _log);
            var service = new NetworkControlService(store, firewall, scheduler, SystemClock.Instance, _log, _executablePath);

            foreach (var action in request.Actions)
            {
                ElevatedActionResult result;
                try
                {
                    result = await service.RunActionAsync(action, source, request.RequestId, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _log.Error("Helper", $"执行操作项 {action.ActionId} 异常", ex);
                    result = new ElevatedActionResult
                    {
                        ActionId = action.ActionId,
                        Success = false,
                        Outcome = Models.OperationOutcome.Failure,
                        Message = $"操作项执行异常：{ex.Message}"
                    };
                }
                response.Results.Add(result);
            }

            response.SuccessOverall = response.Results.All(r => r.Success);
        }
        catch (Exception ex)
        {
            _log.Error("Helper", "提权请求失败", ex);
            response.SuccessOverall = false;
            response.FatalError = ex.Message;
        }
        finally
        {
            response.CompletedUtc = DateTimeOffset.UtcNow;
            try
            {
                HelperRequestCodec.WriteResult(_paths, response);
            }
            catch (Exception ex)
            {
                _log.Error("Helper", "写入提权结果失败", ex);
                exitCode = 2;
            }
        }

        return exitCode;
    }

    public async Task<int> RunScheduledTaskAsync(string taskId, CancellationToken cancellationToken = default)
    {
        try
        {
            var store = new StateRepository(_paths);
            var firewall = new ComFirewallManager();
            var scheduler = new TaskSchedulerRegistrar(_paths, _executablePath, _log);
            var service = new NetworkControlService(store, firewall, scheduler, SystemClock.Instance, _log, _executablePath);
            var result = await service.ExecuteScheduledTaskAsync(taskId, cancellationToken).ConfigureAwait(false);
            _log.Info("ScheduledTask", result.Message);
            return result.ExitCode;
        }
        catch (Exception ex)
        {
            _log.Error("ScheduledTask", "计划任务辅助进程异常", ex);
            return 2;
        }
    }
}
