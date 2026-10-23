using System.IO;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;

namespace NetworkAccessManager.App.Services;

public sealed class UiOperationOutcome
{
    public ElevatedRequest Request { get; init; } = new();
    public ElevatedResponse? Response { get; init; }
    public ElevationInvocationResult? Invocation { get; init; }
    public bool UserCancelled { get; init; }
    public bool TimedOut { get; init; }
    public string? Error { get; init; }
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<ElevatedActionResult> Results => Response?.Results ?? (IReadOnlyList<ElevatedActionResult>)Array.Empty<ElevatedActionResult>();
    public bool AnyFailure => Response is null
        ? !UserCancelled
        : Response.FatalError is not null || Response.Results.Any(r => !r.Success);
    public OperationOutcome Outcome
    {
        get
        {
            if (UserCancelled) return OperationOutcome.Failure;
            if (Response is null) return OperationOutcome.Warning;
            if (!string.IsNullOrWhiteSpace(Response.FatalError)) return OperationOutcome.Failure;
            if (Response.Results.Any(r => !r.Success)) return OperationOutcome.Failure;
            if (Response.Results.Any(r => r.Outcome == OperationOutcome.Warning)) return OperationOutcome.Warning;
            if (Response.Results.Any(r => r.Outcome == OperationOutcome.Info)) return OperationOutcome.Info;
            return OperationOutcome.Success;
        }
    }
}

/// <summary>
/// The UI never modifies firewall rules directly. It delegates to the elevated
/// helper through the standard UAC shell verb and displays the helper's verified
/// result. If UAC is declined or no result arrives, the UI records the failure
/// without claiming that any rule changed.
/// </summary>
public sealed class UiOperationService
{
    private readonly AppPaths _paths;
    private readonly IAppLog _log;
    private readonly StateRepository _store;
    private readonly ElevationClient _client;

    public UiOperationService(AppPaths paths, IAppLog log)
    {
        _paths = paths;
        _log = log;
        _store = new StateRepository(paths);
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
            executable = Path.Combine(AppContext.BaseDirectory, "NetworkAccessManager.exe");
        _client = new ElevationClient(paths, executable, log);
    }

    public async Task<UiOperationOutcome> ExecuteAsync(
        IReadOnlyList<ElevatedAction> actions,
        string operationLabel,
        CancellationToken cancellationToken = default)
    {
        if (actions.Count == 0)
        {
            return new UiOperationOutcome
            {
                Summary = "没有可执行的操作项。",
                Error = "没有可执行的操作项。",
                UserCancelled = false
            };
        }

        var request = new ElevatedRequest
        {
            RequestId = Guid.NewGuid().ToString("N"),
            UserSid = WindowsPrivilege.CurrentUserSid(),
            CreatedUtc = DateTimeOffset.UtcNow,
            Actions = actions.ToList()
        };

        var invocation = await _client.InvokeAsync(request, cancellationToken).ConfigureAwait(false);
        var result = new UiOperationOutcome
        {
            Request = request,
            Invocation = invocation,
            Response = invocation.Response,
            UserCancelled = invocation.UserCancelled,
            TimedOut = invocation.TimedOut,
            Error = invocation.Error
        };

        if (invocation.Response is null)
        {
            var message = invocation.UserCancelled
                ? "你取消了管理员授权。未创建或修改任何 Windows 防火墙规则。"
                : invocation.TimedOut
                    ? "等待管理员操作结果超时。无法确认是否已执行；请刷新状态并核对防火墙与历史记录。"
                    : $"操作没有得到可验证的结果：{invocation.Error ?? "未知原因"}。请刷新后检查真实状态，不要假定成功。";
            RecordLocalFailure(operationLabel, actions, request.RequestId, message,
                invocation.UserCancelled ? OperationOutcome.Failure : OperationOutcome.Warning);
            return new UiOperationOutcome
            {
                Request = request,
                Invocation = invocation,
                UserCancelled = invocation.UserCancelled,
                TimedOut = invocation.TimedOut,
                Error = invocation.Error,
                Summary = message
            };
        }

        if (!string.IsNullOrWhiteSpace(invocation.Response.FatalError))
        {
            RecordLocalFailure(operationLabel, actions, request.RequestId,
                "管理员辅助进程拒绝了请求：" + invocation.Response.FatalError, OperationOutcome.Failure);
        }

        var summaryLines = new List<string>();
        if (!string.IsNullOrWhiteSpace(invocation.Response.FatalError))
            summaryLines.Add("请求失败：" + invocation.Response.FatalError);
        foreach (var item in invocation.Response.Results)
        {
            var status = item.Success
                ? item.Outcome == OperationOutcome.Info ? "信息" : "成功"
                : "失败";
            summaryLines.Add($"[{status}] {item.Message}");
        }

        return new UiOperationOutcome
        {
            Request = request,
            Invocation = invocation,
            Response = invocation.Response,
            Error = invocation.Response.FatalError,
            Summary = summaryLines.Count > 0
                ? string.Join(Environment.NewLine, summaryLines)
                : "管理员辅助进程返回了空结果。"
        };
    }

    private void RecordLocalFailure(
        string operationLabel,
        IReadOnlyList<ElevatedAction> actions,
        string correlationId,
        string message,
        OperationOutcome outcome)
    {
        try
        {
            var first = actions.FirstOrDefault();
            var targets = actions
                .Select(a => a.Target)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .ToList();
            var targetText = targets.Count == 0 ? null : string.Join("; ", targets);
            var detail = actions.Count > 1 ? $"共 {actions.Count} 个操作项。" : null;
            _store.Mutate(state => state.Events.Add(new OperationHistoryEvent
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Operation = operationLabel,
                TargetKind = first?.TargetKind,
                Target = targetText,
                TargetPath = first?.TargetKind == RuleTargetKind.Program ? first.Target : null,
                TaskId = first?.TaskId,
                RuleId = null,
                PlannedUtc = null,
                ActualUtc = null,
                Outcome = outcome,
                Message = message,
                Detail = detail,
                Source = "桌面程序",
                CorrelationId = correlationId
            }));
        }
        catch (Exception ex)
        {
            _log.Error("UI", "记录本地操作失败历史失败", ex);
        }
    }
}
