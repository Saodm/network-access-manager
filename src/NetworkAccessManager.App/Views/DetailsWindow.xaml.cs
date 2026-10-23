using System.Diagnostics;
using System.IO;
using System.Windows;

namespace NetworkAccessManager.App.Views;

public partial class DetailsWindow : Window
{
    private readonly string _detailsText;
    private readonly string? _path;

    public DetailsWindow(string title, string detailsText, string? path)
    {
        InitializeComponent();
        _detailsText = detailsText;
        _path = path;
        DataContext = new { Title = title, DetailsText = detailsText, HasPath = !string.IsNullOrWhiteSpace(path) };
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(_detailsText); }
        catch (Exception ex) { MessageBox.Show("复制失败：" + ex.Message, "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void OpenPath_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_path)) return;
        try
        {
            if (File.Exists(_path))
            {
                var psi = new ProcessStartInfo { FileName = "explorer.exe", UseShellExecute = true };
                psi.ArgumentList.Add("/select," + _path);
                Process.Start(psi);
            }
            else
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrWhiteSpace(dir))
                    Process.Start(new ProcessStartInfo { FileName = dir, UseShellExecute = true });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show("无法在资源管理器中定位：" + ex.Message, "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
