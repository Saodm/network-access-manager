using System.Windows;
using NetworkAccessManager.Core.Network;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.App.Views;

public partial class EthernetScheduleDialog : Window
{
    private readonly bool _initialized;
    private bool _timeValid;

    public EthernetScheduleDialog(IReadOnlyList<EthernetAdapterInfo> adapters)
    {
        InitializeComponent();
        AdapterGrid.ItemsSource = adapters
            .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(a => new AdapterRow(a.Name, a.Description, a.StatusText))
            .ToList();
        _initialized = true;
        UpdateState();
    }

    public int DelayMinutes { get; private set; } = 10;

    private void QuickMinutes_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement element || element.Tag is null) return;
        MinutesTextBox.Text = element.Tag.ToString() ?? "10";
        MinutesTextBox.Focus();
        MinutesTextBox.SelectAll();
    }

    private void Minutes_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (!_initialized) return;
        UpdateState();
    }

    private void Ack_Changed(object sender, RoutedEventArgs e) => UpdateState();

    private void UpdateState()
    {
        var text = MinutesTextBox.Text.Trim();
        var valid = int.TryParse(text, out var minutes) &&
                    minutes >= DurationValidator.MinMinutes &&
                    minutes <= DurationValidator.MaxMinutes;
        _timeValid = valid;
        if (valid)
        {
            DelayMinutes = minutes;
            TimeErrorText.Text = string.Empty;
            var planned = DateTimeOffset.Now.AddMinutes(minutes);
            PreviewTimeText.Text = $"计划执行时间：{planned:yyyy-MM-dd HH:mm}（本机时间）。到时不会自动恢复。";
        }
        else
        {
            TimeErrorText.Text = $"请输入 {DurationValidator.MinMinutes} 到 {DurationValidator.MaxMinutes} 之间的整数分钟数。";
            PreviewTimeText.Text = "尚未设置有效的延迟时间。";
        }
        ConfirmButton.IsEnabled = valid && AckCheck.IsChecked == true;
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (!_timeValid || AckCheck.IsChecked != true) return;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private sealed record AdapterRow(string Name, string Description, string StatusText);
}
