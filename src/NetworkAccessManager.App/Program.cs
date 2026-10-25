using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using NetworkAccessManager.App.Services;
using NetworkAccessManager.App.Views;
using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;

namespace NetworkAccessManager.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var helperRequest = FindArgument(args, HelperProtocol.ElevatedRequestArgument);
        var scheduledTaskId = FindArgument(args, HelperProtocol.ExecuteTaskArgument);
        var isHelperMode = helperRequest is not null || scheduledTaskId is not null;

        AppPaths paths;
        try
        {
            paths = AppPaths.CreateDefault();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"无法确定数据目录：{ex.Message}", "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Error);
            return 2;
        }

        IAppLog log;
        string? loggingError = null;
        try
        {
            paths.EnsureDirectories();
            log = new FileAppLog(paths.LogsDirectory, isHelperMode ? "helper" : "ui");
        }
        catch (Exception ex)
        {
            log = NullAppLog.Instance;
            loggingError = ex.Message;
        }

        if (helperRequest is not null)
            return RunHelperRequest(helperRequest, paths, log);
        if (scheduledTaskId is not null)
            return RunScheduledTask(scheduledTaskId, paths, log);

        return RunUi(paths, log, loggingError, args);
    }

    private static int RunHelperRequest(string encodedRequest, AppPaths paths, IAppLog log)
    {
        try
        {
            var executable = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "NetworkAccessManager.exe");
            var host = new HelperHost(paths, executable, log);
            var result = host.RunElevatedRequestAsync(encodedRequest).GetAwaiter().GetResult();
            log.Info("Helper", $"提权请求处理结束，退出码 {result}。");
            return result;
        }
        catch (Exception ex)
        {
            log.Error("Helper", "提权请求处理出现未捕获异常", ex);
            return 2;
        }
    }

    private static int RunScheduledTask(string taskId, AppPaths paths, IAppLog log)
    {
        try
        {
            var executable = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "NetworkAccessManager.exe");
            var host = new HelperHost(paths, executable, log);
            var result = host.RunScheduledTaskAsync(taskId).GetAwaiter().GetResult();
            log.Info("ScheduledTask", $"定时任务处理结束，退出码 {result}。");
            return result;
        }
        catch (Exception ex)
        {
            log.Error("ScheduledTask", "定时任务处理出现未捕获异常", ex);
            return 2;
        }
    }

    private static int RunUi(AppPaths paths, IAppLog log, string? loggingError, string[] args)
    {
        // A helper invocation or multiple concurrent UI instances must never be
        // allowed to race over the same mutable state.
        var dataRootHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(paths.RootDirectory.ToLowerInvariant())))[..16];
        var mutexName = $"Local\\NetworkAccessManager.UI.{dataRootHash}";
        var isElevated = WindowsPrivilege.IsAdministrator();
        using var mutex = new Mutex(initiallyOwned: true, mutexName, out var createdNew);
        if (!createdNew)
        {
            var message = isElevated
                ? "本工具已有一个窗口在运行。当前“以管理员身份运行”的启动被单实例保护拦截，未执行任何操作。\n\n请先完全关闭已打开的本工具窗口（包括任务栏和系统托盘中的窗口），再重新右键 NetworkAccessManager.exe，选择“以管理员身份运行”。"
                : "本工具已经有一个窗口在运行。\n\n它可能已最小化到右下角系统托盘，请双击托盘图标。如果你刚选择了“以管理员身份运行”但没有看到管理员窗口，请先从托盘退出所有实例，再右键 exe 以管理员身份启动。";
            MessageBox.Show(message, "网络访问管理器", MessageBoxButton.OK,
                isElevated ? MessageBoxImage.Warning : MessageBoxImage.Information);
            return 0;
        }

        var app = new Application
        {
            ShutdownMode = ShutdownMode.OnMainWindowClose
        };
        app.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("pack://application:,,,/NetworkAccessManager;component/Themes/Theme.xaml", UriKind.Absolute)
        });

        app.DispatcherUnhandledException += (_, eventArgs) =>
        {
            log.Error("UI", "未处理的界面异常", eventArgs.Exception);
            MessageBox.Show(
                $"程序遇到未处理的错误：{eventArgs.Exception.Message}\n\n详细信息已写入日志：{(log is FileAppLog fileLog ? fileLog.LogDirectory : paths.LogsDirectory)}",
                "网络访问管理器",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            eventArgs.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) =>
            log.Error("UI", "未处理的进程异常", eventArgs.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, eventArgs) =>
        {
            log.Error("UI", "未观察的异步任务异常", eventArgs.Exception);
            eventArgs.SetObserved();
        };

        try
        {
            log.Info("UI", $"启动桌面界面前检查完成。数据目录={paths.RootDirectory}；日志目录={paths.LogsDirectory}；管理员权限={isElevated}。");
            var window = new MainWindow(paths, log, loggingError);
            app.MainWindow = window;
            return app.Run(window);
        }
        catch (Exception ex)
        {
            log.Error("UI", "主窗口启动失败", ex);
            MessageBox.Show($"主窗口启动失败：{ex.Message}", "网络访问管理器", MessageBoxButton.OK, MessageBoxImage.Error);
            return 1;
        }
        finally
        {
            try { mutex.ReleaseMutex(); } catch { }
        }
    }

    private static string? FindArgument(string[] args, string prefix)
    {
        foreach (var argument in args)
        {
            if (argument.StartsWith(prefix, StringComparison.Ordinal))
                return argument[prefix.Length..];
        }
        return null;
    }
}
