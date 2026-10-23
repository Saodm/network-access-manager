using System.Windows.Media;
using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.Models;

public enum EffectiveTaskState
{
    Waiting,
    Due,
    Overdue,
    Running,
    StaleRunning,
    Succeeded,
    Failed,
    Cancelled
}

public sealed class RuleStatusView
{
    public required ManagedRuleRecord Record { get; init; }
    public FirewallRuleInspection? Inspection { get; init; }
    public FirewallAvailability Availability { get; init; } = new();
    public DateTimeOffset Now { get; init; }

    public string RuleId => Record.RuleId;
    public string RuleIdShort => Record.RuleId.Length > 8 ? Record.RuleId[..8] : Record.RuleId;
    public string TargetKindText => Record.TargetKind == RuleTargetKind.Program ? "程序" : "网络目标";
    public string TargetText => Record.Target;
    public string DirectionText => Record.Direction.ToShortChinese();
    public string FirewallRuleName => Record.FirewallRuleName;
    public string CreatedText => TimeDisplay.LocalDateTime(Record.CreatedUtc);
    public bool IsActiveRecord => Record.Status == ManagedRuleStatus.Active;
    public bool IsVerified => IsActiveRecord && Inspection?.State == RuleInspectionState.Verified;
    public bool IsMissing => IsActiveRecord && Inspection?.State == RuleInspectionState.Missing;
    public bool IsMismatched => IsActiveRecord && Inspection?.State == RuleInspectionState.Mismatched;
    public bool IsUnknown => IsActiveRecord && (Inspection is null || Inspection.State == RuleInspectionState.Unknown);
    public bool IdentityMatches => Inspection?.IdentityMatches == true;
    public bool CanAttemptRemoval => IsActiveRecord;

    public string StatusText
    {
        get
        {
            if (!IsActiveRecord)
            {
                return Record.Status switch
                {
                    ManagedRuleStatus.RemovedByUser => "已解除",
                    ManagedRuleStatus.RemovedExternally => "已被外部移除",
                    ManagedRuleStatus.CreationFailed => "创建失败",
                    _ => "历史规则"
                };
            }
            if (Inspection is null) return "状态未知（未检查）";
            return Inspection.State switch
            {
                RuleInspectionState.Verified => "生效中（已核对）",
                RuleInspectionState.Missing => "已不存在（状态不一致）",
                RuleInspectionState.Mismatched => "被外部修改",
                RuleInspectionState.Unknown => "已登记（无法实时复核）",
                _ => "未知"
            };
        }
    }

    public string VerifiedText => Record.VerifiedUtc is null
        ? "无记录"
        : TimeDisplay.LocalDateTime(Record.VerifiedUtc);

    public string StatusDetail
    {
        get
        {
            if (!IsActiveRecord) return Record.Note ?? "该规则已不在生效状态。";
            if (Inspection is null) return "尚未读取 Windows 防火墙。";
            var detail = Inspection.Detail;
            if (Inspection.State == RuleInspectionState.Unknown)
                detail += $" 上次由辅助进程核验：{VerifiedText}。当前会话无法读取实际防火墙规则。";
            else
                detail += $" 最后核验：{VerifiedText}。";
            if (!string.IsNullOrWhiteSpace(Record.Note)) detail += " " + Record.Note;
            return detail;
        }
    }

    public Brush StatusBrush => IsVerified
        ? Infrastructure.UiBrushes.Red
        : IsActiveRecord
            ? Infrastructure.UiBrushes.Orange
            : Infrastructure.UiBrushes.Gray;

    public string OutcomeText => IsVerified ? "阻断生效" : "不视为生效";
    public string DisplayTarget => Record.TargetKind == RuleTargetKind.Program
        ? System.IO.Path.GetFileName(Record.Target)
        : Record.Target;
    public string SearchText => string.Join(' ', Record.RuleId, Record.Target, Record.FirewallRuleName, StatusText, DirectionText, TargetKindText);
}

public sealed class ScheduledTaskView
{
    public required ScheduledTaskRecord Record { get; init; }
    public DateTimeOffset Now { get; init; }

    public string TaskId => Record.TaskId;
    public string TaskIdShort => Record.TaskId.Length > 8 ? Record.TaskId[..8] : Record.TaskId;
    public string ModeText => Record.ModeText;
    public string TargetKindText => Record.TargetKind == RuleTargetKind.Program ? "程序" : "网络目标";
    public string TargetText => Record.Target;
    public string DisplayTarget => Record.TargetKind == RuleTargetKind.Program
        ? System.IO.Path.GetFileName(Record.Target)
        : Record.Target;
    public string DirectionText => Record.Directions.ToChinese();
    public string CreatedText => TimeDisplay.LocalDateTime(Record.CreatedUtc);
    public string PlannedText => TimeDisplay.LocalDateTime(Record.PlannedUtc);
    public string StartedText => TimeDisplay.LocalDateTime(Record.StartedUtc);
    public string CompletedText => TimeDisplay.LocalDateTime(Record.CompletedUtc);
    public string ScheduledTaskName => Record.ScheduledTaskName;
    public string ResultText => Record.ResultMessage ?? Record.FailureReason ?? "—";
    public IReadOnlyList<string> RuleIds => Record.PlannedRules.Select(r => r.RuleId).ToList();

    public EffectiveTaskState EffectiveState
    {
        get
        {
            if (Record.Status == ScheduledTaskStatus.Pending)
            {
                var due = Record.PlannedUtc;
                if (Now >= due.AddMinutes(2)) return EffectiveTaskState.Overdue;
                if (Now >= due) return EffectiveTaskState.Due;
                return EffectiveTaskState.Waiting;
            }
            if (Record.Status == ScheduledTaskStatus.Running)
            {
                if (Record.StartedUtc is { } started && Now - started > TimeSpan.FromMinutes(10))
                    return EffectiveTaskState.StaleRunning;
                return EffectiveTaskState.Running;
            }
            return Record.Status switch
            {
                ScheduledTaskStatus.Succeeded => EffectiveTaskState.Succeeded,
                ScheduledTaskStatus.Failed => EffectiveTaskState.Failed,
                ScheduledTaskStatus.Cancelled => EffectiveTaskState.Cancelled,
                _ => EffectiveTaskState.Waiting
            };
        }
    }

    public bool IsPendingLike => EffectiveState is EffectiveTaskState.Waiting or EffectiveTaskState.Due or EffectiveTaskState.Overdue or EffectiveTaskState.Running or EffectiveTaskState.StaleRunning;
    public bool CanCancel => Record.Status == ScheduledTaskStatus.Pending;
    public bool IsOverdue => EffectiveState == EffectiveTaskState.Overdue;
    public bool IsFailure => EffectiveState is EffectiveTaskState.Failed or EffectiveTaskState.StaleRunning;
    public bool IsAutoUnblock => Record.ExecutionAction == ScheduledExecutionAction.Unblock;

    public string StatusText => EffectiveState switch
    {
        EffectiveTaskState.Waiting => Record.Mode == ScheduledMode.DelayedBlock ? "等待延迟禁止" : "等待执行",
        EffectiveTaskState.Due => "已到计划时间，等待系统执行",
        EffectiveTaskState.Overdue => "已超时，等待系统补执行",
        EffectiveTaskState.Running => "执行中",
        EffectiveTaskState.StaleRunning => "执行状态未知（可能中断）",
        EffectiveTaskState.Succeeded => "已完成",
        EffectiveTaskState.Failed => "执行失败",
        EffectiveTaskState.Cancelled => "已取消",
        _ => "未知"
    };

    public string RemainingText
    {
        get
        {
            if (Record.Status != ScheduledTaskStatus.Pending) return "—";
            var delta = Record.PlannedUtc - Now;
            if (delta <= TimeSpan.Zero) return "已到预定时间";
            if (delta.TotalDays >= 1) return $"{(int)delta.TotalDays} 天 {delta.Hours} 小时";
            if (delta.TotalHours >= 1) return $"{(int)delta.TotalHours} 小时 {delta.Minutes} 分钟";
            if (delta.TotalMinutes >= 1) return $"{(int)delta.TotalMinutes} 分 {delta.Seconds} 秒";
            return $"{Math.Max(1, delta.Seconds)} 秒";
        }
    }

    public Brush StatusBrush => IsPendingLike
        ? (Record.Status == ScheduledTaskStatus.Running ? Infrastructure.UiBrushes.Blue : Infrastructure.UiBrushes.Orange)
        : IsFailure ? Infrastructure.UiBrushes.Red : Infrastructure.UiBrushes.ForTaskStatus(Record.Status);

    public string FailureText => Record.FailureReason ?? (Record.Status == ScheduledTaskStatus.Failed ? "未提供失败原因" : "—");
    public string ExecutionActionText => Record.ExecutionAction == ScheduledExecutionAction.Block ? "创建阻断规则" : "解除本工具规则";
    public string SearchText => string.Join(' ', TaskId, ModeText, TargetText, StatusText, ResultText, ScheduledTaskName, DirectionText, CreatedText, PlannedText);
}

public sealed class TargetPolicyView
{
    public string Text { get; init; } = "未禁止";
    public string Detail { get; init; } = "没有由本工具创建且处于生效状态的规则。";
    public PolicyStateKind Kind { get; init; } = PolicyStateKind.Normal;
    public BlockDirections VerifiedDirections { get; init; }
    public BlockDirections ProgramRuleDirections { get; init; }
    public BlockDirections NetworkRuleDirections { get; init; }
    public bool HasActiveVerifiedRule => VerifiedDirections != BlockDirections.None;
    public bool HasManagedActiveRule { get; init; }
    public bool HasInconsistentRule { get; init; }
    public bool HasUnknownRule { get; init; }
    public bool HasPendingTask { get; init; }
    public bool HasFailure { get; init; }
    public bool HasOverdueTask { get; init; }
    public int PendingTaskCount { get; init; }
    public int FailedTaskCount { get; init; }
    public int ActiveRuleCount { get; init; }
    public int TargetRuleImpactCount { get; init; }
    public DateTimeOffset? NextAutoUnblockUtc { get; init; }
    public DateTimeOffset? NextPlannedTaskUtc { get; init; }
    public string? NextTaskSummary { get; init; }
    public IReadOnlyList<RuleStatusView> MatchingRules { get; init; } = Array.Empty<RuleStatusView>();
    public IReadOnlyList<ScheduledTaskView> MatchingTasks { get; init; } = Array.Empty<ScheduledTaskView>();

    public Brush Brush => Infrastructure.UiBrushes.ForPolicy(Kind);
    public string ActiveDirectionsText => VerifiedDirections == BlockDirections.None ? "—" : VerifiedDirections.ToChinese();
    public bool IsBlocked => HasActiveVerifiedRule;
    public bool IsLimited => Kind == PolicyStateKind.Limited;
    public string SearchText => string.Join(' ', Text, Detail, ActiveDirectionsText);
}

public sealed class FilterOption
{
    public string Key { get; init; } = "all";
    public string Label { get; init; } = "全部";
    public override string ToString() => Label;
}
