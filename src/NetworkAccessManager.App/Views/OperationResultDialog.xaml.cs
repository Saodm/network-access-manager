using System.Text;
using System.Windows;
using System.Windows.Media;
using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.App.Services;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;

namespace NetworkAccessManager.App.Views;

public sealed class OperationResultRow
{
    public string StatusText { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public string Identifiers { get; init; } = "—";
}

public partial class OperationResultDialog : Window
{
    private readonly UiOperationOutcome _outcome;

    public OperationResultDialog(UiOperationOutcome outcome)
    {
        InitializeComponent();
        _outcome = outcome;
        var rows = outcome.Results.Select(r => new OperationResultRow
        {
            StatusText = r.Success ? (r.Outcome == OperationOutcome.Info ? "信息" : "成功") : "失败",
            Message = r.Message,
            Identifiers = BuildIdentifiers(r)
        }).ToList();

        var title = outcome.UserCancelled
            ? "管理员授权已取消，未执行操作"
            : outcome.Response is null
                ? outcome.TimedOut ? "操作结果未知" : "操作未完成"
                : !string.IsNullOrWhiteSpace(outcome.Response.FatalError)
                    ? "操作失败"
                    : rows.Count == 0
                        ? "管理员进程返回空结果"
                        : rows.All(r => r.StatusText == "成功")
                            ? "操作已成功并通过结果校验"
                            : rows.All(r => r.StatusText is "成功" or "信息")
                                ? "操作已完成（含信息项）"
                                : rows.All(r => r.StatusText == "失败")
                                    ? "操作失败"
                                    : "操作部分完成";
        var brush = outcome.Outcome switch
        {
            OperationOutcome.Success => UiBrushes.Green,
            OperationOutcome.Warning => UiBrushes.Orange,
            OperationOutcome.Failure => UiBrushes.Red,
            _ => UiBrushes.Blue
        };
        var footer = outcome.UserCancelled
            ? "用户取消了 UAC。Windows 防火墙、任务计划程序与本工具状态都没有被修改。"
            : outcome.Response is null
                ? "请重新打开主窗口刷新，并检查任务历史和 Windows 防火墙实际规则；不要仅凭本对话框认定成功。"
                : "成功：规则/任务已由管理员辅助进程创建或删除并返回结果；失败：未完成或部分完成，详见逐项结果。若结果为“部分完成”，请按项检查后再操作。";

        DataContext = new
        {
            OutcomeTitle = title,
            OutcomeBrush = brush,
            Caption = $"请求 ID：{outcome.Request.RequestId}",
            Summary = outcome.Summary,
            Rows = rows,
            Footer = footer
        };
    }

    public event EventHandler? HistoryRequested;

    private static string BuildIdentifiers(ElevatedActionResult result)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(result.TaskId)) parts.Add("任务 " + result.TaskId);
        if (result.RuleIds.Count > 0) parts.Add("规则 " + string.Join(",", result.RuleIds.Select(id => id.Length > 8 ? id[..8] : id)));
        return parts.Count == 0 ? "—" : string.Join(" · ", parts);
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        var builder = new StringBuilder();
        builder.AppendLine("网络访问管理器操作结果");
        builder.AppendLine("请求 ID：" + _outcome.Request.RequestId);
        builder.AppendLine(_outcome.Summary);
        foreach (var result in _outcome.Results)
        {
            builder.AppendLine($"- {(result.Success ? "成功" : "失败")}：{result.Message}");
            if (result.RuleIds.Count > 0) builder.AppendLine("  规则 ID：" + string.Join(",", result.RuleIds));
            if (!string.IsNullOrWhiteSpace(result.TaskId)) builder.AppendLine("  任务 ID：" + result.TaskId);
        }
        try { Clipboard.SetText(builder.ToString()); }
        catch (Exception ex)
        {
            MessageBox.Show("复制失败：" + ex.Message, "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OpenHistory_Click(object sender, RoutedEventArgs e)
    {
        HistoryRequested?.Invoke(this, EventArgs.Empty);
        Close();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
