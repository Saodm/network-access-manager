using System.Diagnostics;
using System.IO;
using System.Windows;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.App.Views;

public partial class HelpWindow : Window
{
    private readonly AppPaths _paths;

    public HelpWindow(AppPaths paths, string version)
    {
        InitializeComponent();
        _paths = paths;
        VersionText.Text = $"网络访问管理器 {version} · Windows 10/11 · 本帮助描述的是当前实际能力与限制";
        DataText.Text = "数据目录：" + paths.RootDirectory;
        LogText.Text = "日志目录：" + paths.LogsDirectory;
    }

    private void OpenData_Click(object sender, RoutedEventArgs e) => Open(_paths.RootDirectory);
    private void OpenLogs_Click(object sender, RoutedEventArgs e) => Open(_paths.LogsDirectory);

    private void Open(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show("无法打开目录：" + ex.Message, "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
