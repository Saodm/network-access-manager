using System.Windows.Media;
using NetworkAccessManager.Core.Models;

namespace NetworkAccessManager.App.Infrastructure;

public enum PolicyStateKind
{
    Normal,
    Blocked,
    Limited,
    Waiting,
    Inconsistent,
    Failure,
    Running,
    Unknown
}

public static class UiBrushes
{
    private static Brush Frozen(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }

    public static readonly Brush Text = Frozen("#20242B");
    public static readonly Brush MutedText = Frozen("#6B7280");
    public static readonly Brush Accent = Frozen("#1F6FB2");
    public static readonly Brush AccentDark = Frozen("#0F4E80");
    public static readonly Brush AccentSoft = Frozen("#E8F2FC");
    public static readonly Brush Selection = Frozen("#2D7DD2");
    public static readonly Brush Green = Frozen("#197A43");
    public static readonly Brush GreenSoft = Frozen("#E8F5ED");
    public static readonly Brush Red = Frozen("#B42318");
    public static readonly Brush RedSoft = Frozen("#FDECEC");
    public static readonly Brush Orange = Frozen("#A34D07");
    public static readonly Brush OrangeSoft = Frozen("#FFF3E5");
    public static readonly Brush Blue = Frozen("#1A68B0");
    public static readonly Brush BlueSoft = Frozen("#EAF3FC");
    public static readonly Brush Gray = Frozen("#6B7280");
    public static readonly Brush GraySoft = Frozen("#EEF0F3");
    public static readonly Brush Critical = Frozen("#8F1D17");
    public static readonly Brush White = Frozen("#FFFFFF");
    public static readonly Brush WarningBackground = Frozen("#FFF7E0");
    public static readonly Brush WarningBorder = Frozen("#E5C06A");

    public static Brush ForPolicy(PolicyStateKind kind) => kind switch
    {
        PolicyStateKind.Blocked => Red,
        PolicyStateKind.Limited => Blue,
        PolicyStateKind.Waiting => Orange,
        PolicyStateKind.Inconsistent => Orange,
        PolicyStateKind.Failure => Red,
        PolicyStateKind.Running => Blue,
        PolicyStateKind.Unknown => Orange,
        _ => Gray
    };

    public static Brush BackgroundForPolicy(PolicyStateKind kind) => kind switch
    {
        PolicyStateKind.Blocked => RedSoft,
        PolicyStateKind.Limited => BlueSoft,
        PolicyStateKind.Waiting => OrangeSoft,
        PolicyStateKind.Inconsistent => OrangeSoft,
        PolicyStateKind.Failure => RedSoft,
        PolicyStateKind.Running => BlueSoft,
        PolicyStateKind.Unknown => OrangeSoft,
        _ => GraySoft
    };

    public static Brush ForRisk(RiskLevel risk) => risk switch
    {
        RiskLevel.Critical => Critical,
        RiskLevel.High => Red,
        RiskLevel.Caution => Orange,
        _ => Gray
    };

    public static Brush BackgroundForRisk(RiskLevel risk) => risk switch
    {
        RiskLevel.Critical => RedSoft,
        RiskLevel.High => RedSoft,
        RiskLevel.Caution => OrangeSoft,
        _ => GraySoft
    };

    public static Brush ForNetwork(NetworkActivityLevel level, bool hasConnections) => level switch
    {
        NetworkActivityLevel.Active => Green,
        NetworkActivityLevel.Listening => Blue,
        _ => hasConnections ? Blue : Gray
    };

    public static Brush ForOutcome(OperationOutcome outcome) => outcome switch
    {
        OperationOutcome.Success => Green,
        OperationOutcome.Warning => Orange,
        OperationOutcome.Failure => Red,
        _ => Blue
    };

    public static Brush ForTaskStatus(ScheduledTaskStatus status) => status switch
    {
        ScheduledTaskStatus.Pending => Orange,
        ScheduledTaskStatus.Running => Blue,
        ScheduledTaskStatus.Succeeded => Green,
        ScheduledTaskStatus.Failed => Red,
        ScheduledTaskStatus.Cancelled => Gray,
        _ => Gray
    };
}
