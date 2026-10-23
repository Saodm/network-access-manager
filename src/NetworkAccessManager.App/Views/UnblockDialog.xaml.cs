using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using NetworkAccessManager.App.Infrastructure;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.Core.Models;

namespace NetworkAccessManager.App.Views;

public sealed class UnblockChoiceItem : ObservableObject
{
    private bool _isSelected;

    public UnblockChoiceItem(UiUnblockTarget target, bool selected)
    {
        Target = target;
        _isSelected = selected;
    }

    public UiUnblockTarget Target { get; }
    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }

    public string Display => Target.Display;
    public string KindText => Target.Kind == RuleTargetKind.Program ? "程序" : "网络目标";
    public string DirectionText => Target.DirectionsText;
    public string Detail => Target.Detail;
    public string StatusText => Target.StatusText;
    public Brush StatusBrush => Target.HasInconsistentRule ? UiBrushes.Orange : UiBrushes.Red;
    public string RulesSummary => string.Join("；", Target.Rules.Select(r =>
        $"{r.DirectionText} · {r.StatusText} · {r.RuleIdShort}"));
    public string RuleCountText => $"{Target.Rules.Count} 条规则";
}

public partial class UnblockDialog : Window
{
    private readonly ObservableCollection<UnblockChoiceItem> _choices;

    public UnblockDialog(IReadOnlyList<UiUnblockTarget> targets)
    {
        InitializeComponent();
        _choices = new ObservableCollection<UnblockChoiceItem>(targets.Select(t =>
            new UnblockChoiceItem(t, selected: t.Rules.Any(r => r.IsActiveRecord))));
        TargetList.ItemsSource = _choices;

        var inconsistent = targets.Count(t => t.HasInconsistentRule);
        WarningText.Text = inconsistent > 0
            ? $"注意：{inconsistent} 个目标包含已被外部删除或修改的规则。解除操作会再次核验身份；不会删除身份不符的规则。"
            : string.Empty;
        WarningText.Visibility = string.IsNullOrWhiteSpace(WarningText.Text) ? Visibility.Collapsed : Visibility.Visible;
        UpdateSummary();
    }

    public IReadOnlyList<UiUnblockTarget> SelectedTargets { get; private set; } = Array.Empty<UiUnblockTarget>();

    private void Choice_Changed(object sender, RoutedEventArgs e) => UpdateSummary();

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var choice in _choices) choice.IsSelected = true;
        UpdateSummary();
    }

    private void SelectNone_Click(object sender, RoutedEventArgs e)
    {
        foreach (var choice in _choices) choice.IsSelected = false;
        UpdateSummary();
    }

    private void UpdateSummary()
    {
        var selected = _choices.Where(c => c.IsSelected).Select(c => c.Target).ToList();
        SelectedTargets = selected;
        var ruleCount = selected.Sum(t => t.Rules.Count);
        var affectedApps = selected.Count(t => t.Kind == RuleTargetKind.NetworkAddress);
        SummaryText.Text = selected.Count == 0
            ? "没有选中任何目标。"
            : $"将解除 {selected.Count} 个目标的 {ruleCount} 条规则" +
              (affectedApps > 0 ? $"；其中 {affectedApps} 个网络目标规则会影响访问该地址的所有应用。" : "。");
        ConfirmButton.IsEnabled = selected.Count > 0;
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedTargets.Count == 0) return;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
