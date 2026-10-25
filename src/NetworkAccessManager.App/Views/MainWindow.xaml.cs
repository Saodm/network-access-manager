using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using NetworkAccessManager.App.Models;
using NetworkAccessManager.App.Services;
using NetworkAccessManager.App.ViewModels;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Network;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Validation;
using Forms = System.Windows.Forms;

namespace NetworkAccessManager.App.Views;

public partial class MainWindow : Window
{
    private readonly AppPaths _paths;
    private readonly IAppLog _log;
    private readonly MainViewModel _vm;
    private bool _suppressSelection;
    private bool _initialized;
    private Forms.NotifyIcon? _trayIcon;
    private Forms.ToolStripMenuItem? _trayEthernetItem;
    private bool _allowClose;
    private bool _trayHintShown;
    private bool _exitPromptOpen;

    public MainWindow(AppPaths paths, IAppLog log, string? loggingError)
    {
        InitializeComponent();
        _paths = paths;
        _log = log;
        _vm = new MainViewModel(paths, log, loggingError);
        DataContext = _vm;
        _vm.PropertyChanged += Vm_PropertyChanged;
        if (Application.Current is not null)
            Application.Current.SessionEnding += Application_SessionEnding;

        foreach (var grid in new[] { AppProcessGrid, SystemProcessGrid, ConnectionGrid })
        {
            grid.PreviewMouseRightButtonDown += Grid_PreviewMouseRightButtonDown;
            grid.GotKeyboardFocus += Grid_GotKeyboardFocus;
        }
        if (!string.IsNullOrWhiteSpace(loggingError))
            _vm.ReportStatus("日志目录不可写，错误日志将不可用：" + loggingError, Infrastructure.UiBrushes.Orange);
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (_initialized) return;
        _initialized = true;
        InitializeTrayIcon();
        await _vm.InitializeAsync();
    }

    private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_allowClose && _trayIcon is not null)
        {
            e.Cancel = true;
            Hide();
            _log.Info("UI", "关闭窗口已转为系统托盘运行。");
            ShowTrayHint();
            return;
        }

        _vm.Dispose();
        DisposeTrayIcon();
    }

    private void InitializeTrayIcon()
    {
        try
        {
            var resource = Application.GetResourceStream(new Uri("pack://application:,,,/app.ico"));
            if (resource?.Stream is null)
                throw new InvalidOperationException("找不到应用图标资源。");

            using var memory = new MemoryStream();
            resource.Stream.CopyTo(memory);
            memory.Position = 0;
            var icon = new System.Drawing.Icon(memory);

            var menu = new Forms.ContextMenuStrip();
            var showItem = new Forms.ToolStripMenuItem("显示主窗口");
            showItem.Font = new System.Drawing.Font(showItem.Font, System.Drawing.FontStyle.Bold);
            showItem.Click += (_, _) => ShowFromTray();
            _trayEthernetItem = new Forms.ToolStripMenuItem("禁用网络");
            _trayEthernetItem.Click += (_, _) => Dispatcher.BeginInvoke(new Action(() => _ = ToggleEthernetAsync()));
            var exitItem = new Forms.ToolStripMenuItem("退出");
            exitItem.Click += (_, _) => Dispatcher.BeginInvoke(new Action(() => _ = ExitApplicationAsync()));
            menu.Items.Add(showItem);
            menu.Items.Add(new Forms.ToolStripSeparator());
            menu.Items.Add(_trayEthernetItem);
            menu.Items.Add(new Forms.ToolStripSeparator());
            menu.Items.Add(exitItem);
            menu.Opening += (_, _) => UpdateTrayMenu();

            _trayIcon = new Forms.NotifyIcon
            {
                Icon = icon,
                Text = "网络访问管理器",
                Visible = true,
                ContextMenuStrip = menu
            };
            _trayIcon.DoubleClick += (_, _) => ShowFromTray();
            _trayIcon.BalloonTipClicked += (_, _) => ShowFromTray();
            UpdateTrayMenu();
            _log.Info("UI", "系统托盘图标已创建；关闭主窗口将隐藏到托盘。");
        }
        catch (Exception ex)
        {
            _trayIcon = null;
            _trayEthernetItem = null;
            _log.Error("UI", "创建系统托盘图标失败；关闭窗口将直接退出", ex);
        }
    }

    private void Vm_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.EthernetToggleText) or nameof(MainViewModel.CanToggleEthernet))
            UpdateTrayMenu();
    }

    private void Application_SessionEnding(object? sender, SessionEndingCancelEventArgs e)
    {
        _allowClose = true;
        DisposeTrayIcon();
    }

    private void DisposeTrayIcon()
    {
        if (_trayIcon is null) return;
        try
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
        catch
        {
            // Shutdown must never be blocked by a tray cleanup error.
        }
        finally
        {
            _trayIcon = null;
            _trayEthernetItem = null;
        }
    }

    private void ShowTrayHint()
    {
        if (_trayIcon is null || _trayHintShown) return;
        _trayHintShown = true;
        _trayIcon.BalloonTipTitle = "网络访问管理器仍在运行";
        _trayIcon.BalloonTipText = _vm.IsEthernetDisabledByTool
            ? "窗口已隐藏到系统托盘。以太网仍处于禁用状态；双击托盘图标恢复网络。"
            : "窗口已隐藏到系统托盘。双击图标重新打开；退出请使用托盘菜单。";
        _trayIcon.ShowBalloonTip(4000);
    }

    private void ShowFromTray()
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(ShowFromTray));
            return;
        }
        if (!IsVisible) Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        ShowInTaskbar = true;
        Activate();
        Topmost = true;
        Topmost = false;
    }

    private void UpdateTrayMenu()
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(UpdateTrayMenu));
            return;
        }
        if (_trayEthernetItem is null) return;
        _trayEthernetItem.Text = _vm.IsEthernetDisabledByTool ? "恢复网络" : "禁用网络";
        _trayEthernetItem.Enabled = _vm.CanToggleEthernet && !_vm.IsBusy;
        if (_trayIcon is not null)
            _trayIcon.Text = _vm.IsEthernetDisabledByTool ? "网络访问管理器 - 以太网已禁用" : "网络访问管理器";
    }

    private async void EthernetToggleButton_Click(object sender, RoutedEventArgs e) =>
        await ToggleEthernetAsync();

    private async Task ToggleEthernetAsync()
    {
        if (_vm.IsBusy) return;
        if (!IsVisible) ShowFromTray();

        if (_vm.IsEthernetDisabledByTool)
        {
            var dialog = new EthernetDialog(false, _vm.EthernetAdapters, _vm.EthernetDisabledRecords) { Owner = this };
            if (dialog.ShowDialog() != true) return;
            await ExecuteAndShowAsync(
            [
                new ElevatedAction
                {
                    ActionId = Guid.NewGuid().ToString("N"),
                    Kind = ElevatedActionKind.EnableEthernet
                }
            ], "恢复以太网");
            UpdateTrayMenu();
            return;
        }

        var adapters = _vm.EthernetAdapters;
        if (adapters.Count == 0)
        {
            _vm.ReportStatus("未发现物理以太网适配器；无线、VPN 和虚拟网卡不会由“禁用网络”处理。", Infrastructure.UiBrushes.Orange);
            return;
        }

        var disableDialog = new EthernetDialog(true, adapters, Array.Empty<EthernetAdapterRecord>()) { Owner = this };
        if (disableDialog.ShowDialog() != true) return;
        await ExecuteAndShowAsync(
        [
            new ElevatedAction
            {
                ActionId = Guid.NewGuid().ToString("N"),
                Kind = ElevatedActionKind.DisableEthernet
            }
        ], "禁用以太网");
        UpdateTrayMenu();
    }

    private async Task ExitApplicationAsync()
    {
        if (_exitPromptOpen) return;
        _exitPromptOpen = true;
        try
        {
            if (_vm.IsBusy)
            {
                MessageBox.Show("当前正在刷新或执行操作，请稍后再退出。", "网络访问管理器",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (_vm.IsEthernetDisabledByTool)
            {
                var choice = MessageBox.Show(
                    "以太网当前由本工具禁用。\n\n" +
                    "“是”：先恢复 Ethernet 再退出。\n" +
                    "“否”：保持断网并退出（之后需要在 Windows 网络连接中手动启用）。\n" +
                    "“取消”：留在系统托盘。",
                    "退出网络访问管理器",
                    MessageBoxButton.YesNoCancel,
                    MessageBoxImage.Warning);
                if (choice == MessageBoxResult.Cancel) return;
                if (choice == MessageBoxResult.Yes)
                {
                    ShowFromTray();
                    var outcome = await _vm.ExecuteOperationAsync(
                    [
                        new ElevatedAction
                        {
                            ActionId = Guid.NewGuid().ToString("N"),
                            Kind = ElevatedActionKind.EnableEthernet
                        }
                    ], "恢复以太网");
                    new OperationResultDialog(outcome) { Owner = this }.ShowDialog();
                    if (outcome.Response?.SuccessOverall != true)
                    {
                        UpdateTrayMenu();
                        return;
                    }
                }
            }

            _allowClose = true;
            DisposeTrayIcon();
            Close();
            Application.Current.Shutdown();
        }
        finally
        {
            _exitPromptOpen = false;
        }
    }

    private async void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F5)
        {
            e.Handled = true;
            if (!_vm.IsBusy)
                await _vm.RefreshAsync(manual: true);
        }
        else if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control)
        {
            e.Handled = true;
            if (SystemProcessGrid.IsKeyboardFocusWithin)
                SystemProcessSearchBox.Focus();
            else if (LeftTabs.SelectedIndex == 1)
                ConnectionSearchBox.Focus();
            else
                AppProcessSearchBox.Focus();
        }
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        await _vm.RefreshAsync(manual: true);
    }

    private async void BlockButton_Click(object sender, RoutedEventArgs e)
    {
        await ShowBlockDialogAsync();
    }

    private async void UnblockButton_Click(object sender, RoutedEventArgs e)
    {
        await ShowUnblockDialogAsync();
    }

    private async void ScheduleButton_Click(object sender, RoutedEventArgs e)
    {
        await ShowScheduleDialogAsync();
    }

    private void CancelTasksButton_Click(object sender, RoutedEventArgs e)
    {
        OpenHistoryWindow(pendingOnly: true);
    }

    private void HistoryButton_Click(object sender, RoutedEventArgs e)
    {
        OpenHistoryWindow(pendingOnly: false);
    }

    private void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SettingsWindow(_vm.SettingsSnapshot, _paths, _vm.VersionText) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.Result is not null)
            _vm.ApplySettings(dialog.Result);
    }

    private void HelpButton_Click(object sender, RoutedEventArgs e)
    {
        new HelpWindow(_paths, _vm.VersionText) { Owner = this }.ShowDialog();
    }

    private async void NetworkTargetButton_Click(object sender, RoutedEventArgs e)
    {
        var availability = _vm.LastSnapshot?.FirewallAvailability;
        var ready = availability is not null && availability.IsAvailable && availability.CanReadRules && availability.IsCurrentProfileProtected;
        var status = availability?.Error ?? availability?.StatusText;
        var dialog = new NetworkTargetDialog(ready, status) { Owner = this };
        if (dialog.ShowDialog() != true || string.IsNullOrWhiteSpace(dialog.SelectedTarget)) return;
        var action = new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.BlockNetworkAddress,
            TargetKind = RuleTargetKind.NetworkAddress,
            Target = dialog.SelectedTarget,
            Directions = dialog.SelectedDirections
        };
        await ExecuteAndShowAsync(new[] { action }, "按网络目标禁止");
    }

    private async Task ShowBlockDialogAsync()
    {
        var evaluator = _vm.PolicyEvaluator;
        if (evaluator is null)
        {
            _vm.ReportStatus("尚未完成真实数据刷新，暂不能创建规则。", Infrastructure.UiBrushes.Orange);
            return;
        }
        var (processes, connections) = GetActiveSelection();
        if (processes.Count == 0 && connections.Count == 0)
        {
            _vm.ReportStatus("请先选择要阻断的对象。", Infrastructure.UiBrushes.Orange);
            return;
        }

        var programTargets = UiTargetBuilder.BuildProgramTargets(processes, connections, evaluator);
        var networkTargets = connections.Count > 0
            ? UiTargetBuilder.BuildNetworkTargets(connections, evaluator)
            : Array.Empty<UiTargetOption>();
        var allowKindChoice = connections.Count > 0 && programTargets.Count > 0 && networkTargets.Count > 0;
        var initialKind = programTargets.Any(t => t.CanBlock) || programTargets.Count == 0 && networkTargets.Count == 0
            ? RuleTargetKind.Program
            : networkTargets.Any(t => t.CanBlock) ? RuleTargetKind.NetworkAddress : RuleTargetKind.Program;
        if (connections.Count > 0 && networkTargets.Count > 0 && !programTargets.Any(t => t.CanBlock))
            initialKind = RuleTargetKind.NetworkAddress;

        var dialog = new BlockDialog(programTargets, networkTargets, allowKindChoice, initialKind) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.SelectedTargets.Count == 0) return;
        var actions = dialog.SelectedTargets
            .GroupBy(t => t.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Select(t => new ElevatedAction
            {
                ActionId = Guid.NewGuid().ToString("N"),
                Kind = dialog.SelectedKind == RuleTargetKind.Program
                    ? ElevatedActionKind.BlockProgram
                    : ElevatedActionKind.BlockNetworkAddress,
                TargetKind = dialog.SelectedKind,
                Target = t.Value,
                Directions = dialog.SelectedDirections
            })
            .ToList();
        if (actions.Count == 0)
        {
            _vm.ReportStatus("没有可执行的对象，未创建规则。", Infrastructure.UiBrushes.Orange);
            return;
        }
        await ExecuteAndShowAsync(actions, "立即禁止");
    }

    private async Task ShowScheduleDialogAsync()
    {
        var evaluator = _vm.PolicyEvaluator;
        if (evaluator is null)
        {
            _vm.ReportStatus("尚未完成真实数据刷新，暂不能安排任务。", Infrastructure.UiBrushes.Orange);
            return;
        }
        var (processes, connections) = GetActiveSelection();
        if (processes.Count == 0 && connections.Count == 0)
        {
            _vm.ReportStatus("请先选择要安排定时操作的对象。", Infrastructure.UiBrushes.Orange);
            return;
        }

        var programTargets = UiTargetBuilder.BuildProgramTargets(processes, connections, evaluator);
        var networkTargets = connections.Count > 0
            ? UiTargetBuilder.BuildNetworkTargets(connections, evaluator)
            : Array.Empty<UiTargetOption>();
        var allowKindChoice = connections.Count > 0 && programTargets.Count > 0 && networkTargets.Count > 0;
        var initialKind = programTargets.Any(t => t.ActiveDirections != BlockDirections.None || t.CanBlock)
            ? RuleTargetKind.Program
            : networkTargets.Count > 0 ? RuleTargetKind.NetworkAddress : RuleTargetKind.Program;

        var dialog = new ScheduleDialog(programTargets, networkTargets, allowKindChoice, initialKind) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.SelectedTargets.Count == 0) return;
        var actions = new List<ElevatedAction>();
        foreach (var target in dialog.SelectedTargets.GroupBy(t => t.Key, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
        {
            var action = dialog.SelectedMode switch
            {
                ScheduledMode.DelayedBlock => new ElevatedAction
                {
                    ActionId = Guid.NewGuid().ToString("N"),
                    Kind = ElevatedActionKind.ScheduleDelayedBlock,
                    TargetKind = dialog.SelectedKind,
                    Target = target.Value,
                    Directions = dialog.SelectedDirections,
                    DelayMinutes = dialog.SelectedMinutes
                },
                ScheduledMode.TimedBlock => new ElevatedAction
                {
                    ActionId = Guid.NewGuid().ToString("N"),
                    Kind = ElevatedActionKind.ScheduleTimedBlock,
                    TargetKind = dialog.SelectedKind,
                    Target = target.Value,
                    Directions = dialog.SelectedDirections,
                    DelayMinutes = dialog.SelectedMinutes
                },
                ScheduledMode.DelayedUnblock => new ElevatedAction
                {
                    ActionId = Guid.NewGuid().ToString("N"),
                    Kind = ElevatedActionKind.ScheduleDelayedUnblock,
                    TargetKind = dialog.SelectedKind,
                    Target = target.Value,
                    Directions = target.ActiveDirections,
                    DelayMinutes = dialog.SelectedMinutes
                },
                _ => throw new ArgumentOutOfRangeException()
            };
            actions.Add(action);
        }
        await ExecuteAndShowAsync(actions, "定时网络控制");
    }

    private async Task ShowUnblockDialogAsync()
    {
        var (processes, connections) = GetActiveSelection();
        var targets = UiTargetBuilder.BuildUnblockTargets(processes, connections);
        if (targets.Count == 0)
        {
            _vm.ReportStatus("当前选择没有仍处于本工具登记有效状态的阻断规则。", Infrastructure.UiBrushes.Orange);
            return;
        }

        var dialog = new UnblockDialog(targets) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.SelectedTargets.Count == 0) return;
        var actions = dialog.SelectedTargets.Select(t => new ElevatedAction
        {
            ActionId = Guid.NewGuid().ToString("N"),
            Kind = ElevatedActionKind.UnblockTarget,
            TargetKind = t.Kind,
            Target = t.Value
        }).ToList();
        await ExecuteAndShowAsync(actions, "解除本工具规则");
    }

    private async Task ExecuteAndShowAsync(IReadOnlyList<ElevatedAction> actions, string label)
    {
        if (actions.Count == 0)
        {
            _vm.ReportStatus("没有可执行的操作项。", Infrastructure.UiBrushes.Orange);
            return;
        }
        var outcome = await _vm.ExecuteOperationAsync(actions, label);
        var openHistory = false;
        var result = new OperationResultDialog(outcome) { Owner = this };
        result.HistoryRequested += (_, _) => openHistory = true;
        result.ShowDialog();
        if (openHistory)
            OpenHistoryWindow(pendingOnly: false);
    }

    private void OpenHistoryWindow(bool pendingOnly)
    {
        var window = new TaskHistoryWindow(_paths, _log, pendingOnly) { Owner = this };
        window.ShowDialog();
        _ = _vm.RefreshAsync(manual: true);
    }

    private (IReadOnlyList<ProcessRowViewModel> Processes, IReadOnlyList<ConnectionRowViewModel> Connections) GetActiveSelection()
    {
        return _vm.ActiveSelectionScope == SelectionScope.Connections
            ? (Array.Empty<ProcessRowViewModel>(), _vm.ActiveSelectedConnections)
            : (_vm.ActiveSelectedProcesses, Array.Empty<ConnectionRowViewModel>());
    }

    private void AppProcessGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressSelection || !IsLoaded || LeftTabs.SelectedIndex != 0) return;
        var rows = AppProcessGrid.SelectedItems.OfType<ProcessRowViewModel>().ToList();
        CommitGridSelection(SelectionScope.AppProcesses, rows, null);
    }

    private void SystemProcessGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressSelection || !IsLoaded) return;
        var rows = SystemProcessGrid.SelectedItems.OfType<ProcessRowViewModel>().ToList();
        CommitGridSelection(SelectionScope.SystemProcesses, rows, null);
    }

    private void ConnectionGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressSelection || !IsLoaded || LeftTabs.SelectedIndex != 1) return;
        var rows = ConnectionGrid.SelectedItems.OfType<ConnectionRowViewModel>().ToList();
        CommitGridSelection(SelectionScope.Connections, null, rows);
    }

    private void CommitGridSelection(
        SelectionScope scope,
        IReadOnlyList<ProcessRowViewModel>? processes,
        IReadOnlyList<ConnectionRowViewModel>? connections)
    {
        var count = processes?.Count ?? connections?.Count ?? 0;
        if (count == 0)
        {
            if (_vm.ActiveSelectionScope == scope)
                _vm.ClearSelection();
            return;
        }

        _vm.SetSelection(scope, processes, connections);
    }

    private void Grid_GotKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (_suppressSelection || !IsLoaded) return;
        if (sender == AppProcessGrid && LeftTabs.SelectedIndex == 0 && AppProcessGrid.SelectedItems.Count > 0)
            CommitGridSelection(SelectionScope.AppProcesses, AppProcessGrid.SelectedItems.OfType<ProcessRowViewModel>().ToList(), null);
        else if (sender == ConnectionGrid && LeftTabs.SelectedIndex == 1 && ConnectionGrid.SelectedItems.Count > 0)
            CommitGridSelection(SelectionScope.Connections, null, ConnectionGrid.SelectedItems.OfType<ConnectionRowViewModel>().ToList());
        else if (sender == SystemProcessGrid && SystemProcessGrid.SelectedItems.Count > 0)
            CommitGridSelection(SelectionScope.SystemProcesses, SystemProcessGrid.SelectedItems.OfType<ProcessRowViewModel>().ToList(), null);
    }

    private void LeftTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressSelection || !IsLoaded) return;
        // The hidden tab's visual selection can remain, but only the visible
        // tab may become the active target for the bottom action bar.
        if (LeftTabs.SelectedIndex == 0 && AppProcessGrid.SelectedItems.Count > 0)
        {
            _vm.SetSelection(SelectionScope.AppProcesses,
                AppProcessGrid.SelectedItems.OfType<ProcessRowViewModel>().ToList(), null);
        }
        else if (LeftTabs.SelectedIndex == 1 && ConnectionGrid.SelectedItems.Count > 0)
        {
            _vm.SetSelection(SelectionScope.Connections, null,
                ConnectionGrid.SelectedItems.OfType<ConnectionRowViewModel>().ToList());
        }
        else
        {
            _vm.ClearSelection();
        }
    }

    private void Grid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid grid) return;
        var row = FindVisualParent<DataGridRow>(e.OriginalSource as DependencyObject);
        if (row is null || row.Item is null) return;
        if (!row.IsSelected)
        {
            _suppressSelection = true;
            try { grid.UnselectAll(); } finally { _suppressSelection = false; }
            row.IsSelected = true;
            if (ReferenceEquals(grid, AppProcessGrid))
                CommitGridSelection(SelectionScope.AppProcesses, grid.SelectedItems.OfType<ProcessRowViewModel>().ToList(), null);
            else if (ReferenceEquals(grid, SystemProcessGrid))
                CommitGridSelection(SelectionScope.SystemProcesses, grid.SelectedItems.OfType<ProcessRowViewModel>().ToList(), null);
            else if (ReferenceEquals(grid, ConnectionGrid))
                CommitGridSelection(SelectionScope.Connections, null, grid.SelectedItems.OfType<ConnectionRowViewModel>().ToList());
        }
    }

    private void Grid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        var source = e.OriginalSource as DependencyObject;
        if (FindVisualParent<DataGridRow>(source) is null) return;
        OpenDetailsWindow();
    }

    private void ContextBlock_Click(object sender, RoutedEventArgs e) => _ = ShowBlockDialogAsync();

    private void ContextSchedule_Click(object sender, RoutedEventArgs e) => _ = ShowScheduleDialogAsync();

    private async void ContextUnblock_Click(object sender, RoutedEventArgs e) => await ShowUnblockDialogAsync();

    private void OpenDetails_Click(object sender, RoutedEventArgs e) => OpenDetailsWindow();

    private void OpenDetailsWindow()
    {
        if (!_vm.HasSelection)
        {
            _vm.ReportStatus("请先选择一行或多行。", Infrastructure.UiBrushes.Orange);
            return;
        }
        var title = _vm.SelectionTitle;
        var text = BuildDetailsText();
        var window = new DetailsWindow(title, text, _vm.SelectedPath) { Owner = this };
        window.ShowDialog();
    }

    private void CopyDetails_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_vm.HasSelection)
                Clipboard.SetText(BuildDetailsText());
        }
        catch (Exception ex)
        {
            _vm.ReportStatus("复制详情失败：" + ex.Message, Infrastructure.UiBrushes.Red);
        }
    }

    private void CopySelectedPath_Click(object sender, RoutedEventArgs e)
    {
        var paths = new List<string>();
        foreach (var process in _vm.ActiveSelectedProcesses)
            if (!string.IsNullOrWhiteSpace(process.ExecutablePath)) paths.Add(process.ExecutablePath!);
        foreach (var connection in _vm.ActiveSelectedConnections)
            if (!string.IsNullOrWhiteSpace(connection.ProcessPath)) paths.Add(connection.ProcessPath!);
        paths = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (paths.Count == 0)
        {
            _vm.ReportStatus("当前选择没有可复制的可执行文件路径。", Infrastructure.UiBrushes.Orange);
            return;
        }
        try
        {
            Clipboard.SetText(string.Join(Environment.NewLine, paths));
            _vm.ReportStatus($"已复制 {paths.Count} 个可执行文件路径。", Infrastructure.UiBrushes.Green);
        }
        catch (Exception ex)
        {
            _vm.ReportStatus("复制路径失败：" + ex.Message, Infrastructure.UiBrushes.Red);
        }
    }

    private void OpenSelectedPath_Click(object sender, RoutedEventArgs e) => _vm.OpenSelectedPathInExplorer();

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(_paths.RootDirectory);
            Process.Start(new ProcessStartInfo { FileName = _paths.RootDirectory, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _vm.ReportStatus("无法打开数据目录：" + ex.Message, Infrastructure.UiBrushes.Red);
        }
    }

    private string BuildDetailsText()
    {
        var builder = new StringBuilder();
        if (_vm.ActiveSelectionScope == SelectionScope.Connections)
        {
            foreach (var connection in _vm.ActiveSelectedConnections)
                AppendConnectionDetails(builder, connection);
        }
        else
        {
            foreach (var process in _vm.ActiveSelectedProcesses)
                AppendProcessDetails(builder, process);
        }
        if (builder.Length == 0)
            builder.AppendLine("没有可显示的详情。");
        builder.AppendLine();
        builder.AppendLine($"数据目录：{_paths.RootDirectory}");
        builder.AppendLine("说明：规则状态来自最近一次 Windows 防火墙核对；任务状态来自持久化任务记录。未知或不可读字段不填充模拟值。");
        return builder.ToString();
    }

    private static void AppendProcessDetails(StringBuilder builder, ProcessRowViewModel row)
    {
        builder.AppendLine("===== 进程 =====");
        builder.AppendLine($"名称：{row.DisplayName}（{row.ProcessName}）");
        builder.AppendLine($"PID：{row.Pid} · 会话：{row.SessionText} · 启动时间：{row.StartTimeText}");
        builder.AppendLine($"路径：{row.PathDisplay}");
        builder.AppendLine($"分类：{row.CategoryText} · 证据：{row.ClassificationEvidence}");
        builder.AppendLine($"风险：{row.RiskSummary}");
        builder.AppendLine($"签名：{row.SignatureStatusText} · 发布者：{row.PublisherText}");
        builder.AppendLine($"公司：{row.CompanyText} · 版本：{row.FileVersionText}");
        builder.AppendLine($"服务：{row.ServiceSummary}");
        if (row.IsProgramBlockProtected) builder.AppendLine($"保护：{row.ProtectionReason}");
        builder.AppendLine($"网络：{row.NetworkStatusText} · {row.ConnectionCountText}");
        builder.AppendLine($"策略：{row.PolicyText}");
        builder.AppendLine($"规则/任务：{row.PolicyDetail}");
        builder.AppendLine($"说明：{row.Notes}");
        if (row.MatchingTasks.Count > 0)
        {
            builder.AppendLine("相关定时任务：");
            foreach (var task in row.MatchingTasks)
                builder.AppendLine($"  - {task.ModeText} · {task.StatusText} · 计划 {task.PlannedText} · {task.ResultText}");
        }
        if (row.Connections.Count > 0)
        {
            builder.AppendLine("当前网络端点（最多 60 条）：");
            foreach (var connection in row.Connections.Take(60))
                builder.AppendLine($"  - {connection.ProtocolText}/{connection.IpVersionText} {connection.LocalEndpoint} → {connection.RemoteEndpoint} · {connection.TcpStateText}");
        }
        builder.AppendLine($"采集时间：{row.Record.CapturedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine();
    }

    private static void AppendConnectionDetails(StringBuilder builder, ConnectionRowViewModel row)
    {
        builder.AppendLine("===== 网络连接 =====");
        builder.AppendLine($"进程：{row.OwnerText} · 路径：{row.PathDisplay}");
        builder.AppendLine($"协议：{row.ProtocolDetail} · 状态：{row.ActivityText} · TCP 状态：{row.TcpStateText}");
        builder.AppendLine($"本地：{row.LocalEndpoint} · 远程：{row.RemoteEndpoint}");
        builder.AppendLine($"连接 ID：{row.Record.ConnectionId}");
        builder.AppendLine($"策略：{row.PolicyText}");
        builder.AppendLine($"规则/任务：{row.PolicyDetail}");
        builder.AppendLine($"说明：{row.Notes}");
        if (row.MatchingTasks.Count > 0)
        {
            builder.AppendLine("相关定时任务：");
            foreach (var task in row.MatchingTasks)
                builder.AppendLine($"  - {task.ModeText} · {task.StatusText} · 计划 {task.PlannedText} · {task.ResultText}");
        }
        builder.AppendLine($"采集时间：{row.Record.CapturedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine();
    }

    private static T? FindVisualParent<T>(DependencyObject? source) where T : DependencyObject
    {
        while (source is not null)
        {
            if (source is T typed) return typed;
            try { source = VisualTreeHelper.GetParent(source); }
            catch { return null; }
        }
        return null;
    }
}
