using System.Diagnostics;
using System.IO;
using System.Windows;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.App.Views;

public sealed class RefreshIntervalOption
{
    public int Seconds { get; init; }
    public string Label { get; init; } = string.Empty;
    public override string ToString() => Label;
}

public partial class SettingsWindow : Window
{
    private static readonly int[] AllowedIntervals = [3, 5, 10, 15, 30, 60];
    private readonly AppPaths _paths;
    private readonly string _version;

    public SettingsWindow(UiSettings current, AppPaths paths, string version)
    {
        InitializeComponent();
        _paths = paths;
        _version = version;
        DataPathText.Text = paths.RootDirectory;
        LogPathText.Text = paths.LogsDirectory;
        AboutText.Text = $"网络访问管理器 {version} · Windows 防火墙 + 任务计划程序\n" +
                         "界面默认以普通权限运行，修改规则时按需 UAC；若主动以管理员身份启动，则直接复用当前管理员令牌。不安装内核驱动、不保存管理员密码。\n" +
                         "关闭主窗口会隐藏到系统托盘；退出请使用托盘菜单。\n" +
                         "制定规则前请阅读“帮助”中的作用范围和权限说明。";
        StorageHintText.Text = "本程序采用安装目录旁的 data 目录，便于便携使用和审计。若安装到受保护的系统目录，普通权限将无法写入历史和设置，请安装到当前用户可写的位置。";
        var intervals = AllowedIntervals
            .Where(s => s >= 3)
            .Select(s => new RefreshIntervalOption { Seconds = s, Label = $"{s} 秒" })
            .ToList();
        IntervalComboBox.ItemsSource = intervals;
        var selected = intervals.FirstOrDefault(o => o.Seconds == current.RefreshIntervalSeconds) ?? intervals[1];
        IntervalComboBox.SelectedItem = selected;
        AutoRefreshCheckBox.IsChecked = current.AutoRefreshEnabled;
    }

    public UiSettings? Result { get; private set; }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (IntervalComboBox.SelectedItem is not RefreshIntervalOption option)
        {
            ErrorText.Text = "请选择刷新间隔。";
            return;
        }
        Result = new UiSettings
        {
            RefreshIntervalSeconds = option.Seconds,
            AutoRefreshEnabled = AutoRefreshCheckBox.IsChecked == true
        };
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void OpenData_Click(object sender, RoutedEventArgs e) => OpenDirectory(_paths.RootDirectory);
    private void OpenLogs_Click(object sender, RoutedEventArgs e) => OpenDirectory(_paths.LogsDirectory);

    private void OpenDirectory(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            Process.Start(new ProcessStartInfo { FileName = directory, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ErrorText.Text = "无法打开目录：" + ex.Message;
        }
    }
}
