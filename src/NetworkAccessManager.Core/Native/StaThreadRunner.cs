namespace NetworkAccessManager.Core.Native;

/// <summary>
/// Runs a delegate on a dedicated single-threaded-apartment thread, which is
/// required for reliable COM interop with the Windows Firewall automation API.
/// </summary>
internal static class StaThreadRunner
{
    public static T Run<T>(Func<T> action, TimeSpan? timeout = null)
    {
        T result = default!;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                result = action();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        })
        {
            IsBackground = true,
            Name = "NAM-STA-Worker"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        var wait = timeout ?? TimeSpan.FromSeconds(45);
        if (!thread.Join(wait))
            throw new TimeoutException("等待 Windows COM 操作完成超时。");
        if (failure is not null)
            throw new InvalidOperationException($"Windows COM 操作失败：{failure.Message}", failure);
        return result;
    }

    public static void Run(Action action, TimeSpan? timeout = null) =>
        Run(() =>
        {
            action();
            return 0;
        }, timeout);
}
