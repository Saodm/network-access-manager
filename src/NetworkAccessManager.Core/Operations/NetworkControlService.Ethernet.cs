using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Network;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.Core.Operations;

public sealed partial class NetworkControlService
{
    /// <summary>
    /// Disables every physical Ethernet adapter that Windows currently reports
    /// as enabled. The state record is written before the first adapter change
    /// so a crash still leaves enough information for the restore entry.
    /// </summary>
    private ElevatedActionResult ExecuteEthernetDisable(
        ElevatedAction action,
        string source,
        string? correlationId)
    {
        IReadOnlyList<EthernetAdapterInfo> current;
        try
        {
            current = _ethernet.Inspect();
        }
        catch (Exception ex)
        {
            return Failure(action, "读取以太网适配器失败：" + ex.Message, source, correlationId, ex.ToString());
        }

        var enabled = current.Where(a => a.AdminEnabled == true).ToList();
        if (enabled.Count == 0)
        {
            return new ElevatedActionResult
            {
                ActionId = action.ActionId,
                Success = true,
                Outcome = OperationOutcome.Info,
                Message = "没有发现处于启用状态的物理以太网适配器，未做任何更改。"
            };
        }

        var existing = _store.ReadState().State;
        if (existing.Ethernet is { IsDisabledByTool: true, DisabledAdapters.Count: > 0 })
        {
            return new ElevatedActionResult
            {
                ActionId = action.ActionId,
                Success = true,
                Outcome = OperationOutcome.Info,
                Message = "本工具记录显示以太网已经处于禁用状态，请使用“恢复网络”。"
            };
        }

        var now = _clock.UtcNow;
        var records = enabled.Select(a => new EthernetAdapterRecord
        {
            Id = EthernetAdapterInspector.NormalizeId(a.Id),
            Name = a.DisplayName,
            Description = a.Description
        }).ToList();

        try
        {
            _store.Mutate(state =>
            {
                state.Ethernet ??= new EthernetControlState();
                state.Ethernet.IsDisabledByTool = true;
                state.Ethernet.DisabledUtc = now;
                state.Ethernet.DisabledAdapters = records;
                state.Ethernet.Note = "禁用操作进行中；若本工具异常退出，请使用恢复入口。";
            });
        }
        catch (Exception ex)
        {
            return Failure(action, "无法在禁用网络前保存恢复记录，已拒绝执行：" + ex.Message, source, correlationId, ex.ToString());
        }

        EthernetChangeResult change;
        try
        {
            change = _ethernet.Disable(records);
        }
        catch (Exception ex)
        {
            change = new EthernetChangeResult
            {
                Success = false,
                Message = "网络适配器操作异常：" + ex.Message
            };
        }

        var disabledIds = change.ChangedAdapterIds
            .Select(EthernetAdapterInspector.NormalizeId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var disabled = records.Where(r => disabledIds.Contains(r.Id)).ToList();
        var failed = records.Where(r => !disabledIds.Contains(r.Id)).ToList();
        var success = failed.Count == 0 && change.Success;
        var message = success
            ? $"已禁用 {disabled.Count} 个物理以太网适配器。网络连接可能立即断开；本工具会留在系统托盘，可从托盘或主界面恢复网络。"
            : disabled.Count == 0
                ? "未确认禁用任何以太网适配器。" + change.Message
                : $"仅确认禁用 {disabled.Count}/{records.Count} 个以太网适配器；未完成：{string.Join("、", failed.Select(r => r.Name))}。{change.Message}";

        try
        {
            _store.Mutate(state =>
            {
                state.Ethernet ??= new EthernetControlState();
                state.Ethernet.IsDisabledByTool = disabled.Count > 0;
                state.Ethernet.DisabledUtc = disabled.Count > 0 ? now : null;
                state.Ethernet.DisabledAdapters = disabled;
                state.Ethernet.Note = success
                    ? "由本工具禁用；退出程序前请先恢复网络。"
                    : change.Message;
                state.Events.Add(new OperationHistoryEvent
                {
                    TimestampUtc = now,
                    Operation = "禁用以太网",
                    TargetKind = RuleTargetKind.Ethernet,
                    Target = "所有物理以太网适配器",
                    ActualUtc = now,
                    Outcome = success ? OperationOutcome.Success : disabled.Count > 0 ? OperationOutcome.Warning : OperationOutcome.Failure,
                    Message = message,
                    Detail = string.Join(Environment.NewLine,
                        records.Select(r => $"{r.Name}；{r.Description}；{r.Id}")),
                    Source = source,
                    CorrelationId = correlationId
                });
            });
        }
        catch (Exception ex)
        {
            _log.Error("Ethernet", "禁用以太网后保存状态失败", ex);
            return Failure(action,
                "网络适配器可能已禁用，但恢复记录保存失败。请立即在 Windows“网络连接”中手动启用以太网，并检查日志。",
                source, correlationId, ex.ToString());
        }

        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = success,
            Outcome = success ? OperationOutcome.Success : disabled.Count > 0 ? OperationOutcome.Warning : OperationOutcome.Failure,
            Message = message,
            Detail = success ? null : change.Message
        };
    }

    /// <summary>
    /// Re-enables only adapters recorded by a previous Disable operation. It
    /// never enables adapters that the user disabled manually.
    /// </summary>
    private ElevatedActionResult ExecuteEthernetEnable(
        ElevatedAction action,
        string source,
        string? correlationId)
    {
        var state = _store.ReadState().State;
        var records = state.Ethernet?.DisabledAdapters ?? new List<EthernetAdapterRecord>();
        if (records.Count == 0)
        {
            return new ElevatedActionResult
            {
                ActionId = action.ActionId,
                Success = true,
                Outcome = OperationOutcome.Info,
                Message = "本工具没有记录到由它禁用的以太网适配器，未修改任何网络设置。"
            };
        }

        EthernetChangeResult change;
        try
        {
            change = _ethernet.Enable(records);
        }
        catch (Exception ex)
        {
            change = new EthernetChangeResult
            {
                Success = false,
                Message = "网络适配器操作异常：" + ex.Message
            };
        }

        var restoredIds = change.ChangedAdapterIds
            .Select(EthernetAdapterInspector.NormalizeId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var restored = records.Where(r => restoredIds.Contains(r.Id)).ToList();
        var remaining = records.Where(r => !restoredIds.Contains(r.Id)).ToList();
        var success = remaining.Count == 0 && change.Success;
        var message = success
            ? $"已恢复 {restored.Count} 个由本工具禁用的以太网适配器。"
            : restored.Count == 0
                ? "未能恢复以太网适配器。" + change.Message
                : $"已恢复 {restored.Count}/{records.Count} 个；仍需处理：{string.Join("、", remaining.Select(r => r.Name))}。{change.Message}";

        var now = _clock.UtcNow;
        try
        {
            _store.Mutate(s =>
            {
                s.Ethernet ??= new EthernetControlState();
                s.Ethernet.DisabledAdapters = remaining;
                s.Ethernet.IsDisabledByTool = remaining.Count > 0;
                s.Ethernet.DisabledUtc = remaining.Count > 0 ? s.Ethernet.DisabledUtc : null;
                s.Ethernet.Note = remaining.Count > 0 ? change.Message : "已恢复。";
                s.Events.Add(new OperationHistoryEvent
                {
                    TimestampUtc = now,
                    Operation = "恢复以太网",
                    TargetKind = RuleTargetKind.Ethernet,
                    Target = "所有物理以太网适配器",
                    ActualUtc = now,
                    Outcome = success ? OperationOutcome.Success : restored.Count > 0 ? OperationOutcome.Warning : OperationOutcome.Failure,
                    Message = message,
                    Detail = string.Join(Environment.NewLine,
                        records.Select(r => $"{r.Name}；{r.Description}；{r.Id}")),
                    Source = source,
                    CorrelationId = correlationId
                });
            });
        }
        catch (Exception ex)
        {
            _log.Error("Ethernet", "恢复以太网后保存状态失败", ex);
            return Failure(action,
                "网络适配器可能已恢复，但状态记录保存失败。请刷新 Windows 网络连接并检查日志。",
                source, correlationId, ex.ToString());
        }

        return new ElevatedActionResult
        {
            ActionId = action.ActionId,
            Success = success,
            Outcome = success ? OperationOutcome.Success : restored.Count > 0 ? OperationOutcome.Warning : OperationOutcome.Failure,
            Message = message,
            Detail = success ? null : change.Message
        };
    }
}
