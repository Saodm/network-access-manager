using NetworkAccessManager.Core.Diagnostics;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.Core.Operations;

/// <summary>
/// Serializes rule/schedule mutations across the desktop UI helper, scheduled
/// helpers and any manually started helpers. This closes the race between the
/// "check existing rules" and "create new rules" steps.
/// </summary>
public sealed class OperationFileLock : IDisposable
{
    private readonly FileStream _stream;

    private OperationFileLock(FileStream stream)
    {
        _stream = stream;
    }

    public static OperationFileLock Acquire(AppPaths paths, IAppLog? log = null, TimeSpan? timeout = null)
    {
        paths.EnsureDirectories();
        var limit = timeout ?? TimeSpan.FromSeconds(45);
        var started = DateTime.UtcNow;
        var lockPath = Path.Combine(paths.RootDirectory, "operations.lock");
        Exception? last = null;
        while (DateTime.UtcNow - started < limit)
        {
            try
            {
                var stream = new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.None);
                return new OperationFileLock(stream);
            }
            catch (IOException ex)
            {
                last = ex;
                Thread.Sleep(100);
            }
            catch (UnauthorizedAccessException ex)
            {
                last = ex;
                Thread.Sleep(100);
            }
        }

        log?.Warn("Operations", "获取跨进程操作锁超时。");
        throw new OperationBusyException("另一个网络管理操作正在执行，请稍后重试。", last);
    }

    public void Dispose()
    {
        try { _stream.Dispose(); } catch { }
    }
}

public sealed class OperationBusyException : Exception
{
    public OperationBusyException(string message, Exception? inner = null) : base(message, inner) { }
}
