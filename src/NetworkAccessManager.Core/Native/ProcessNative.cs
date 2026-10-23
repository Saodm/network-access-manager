using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NetworkAccessManager.Core.Native;

internal static class ProcessNative
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle hProcess,
        uint flags,
        StringBuilder lpExeName,
        ref int lpdwSize);

    public static bool TryGetImagePath(int pid, out string? path, out string? error)
    {
        path = null;
        error = null;
        if (pid <= 0)
        {
            error = "系统空闲进程没有可执行文件路径。";
            return false;
        }

        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            var code = Marshal.GetLastWin32Error();
            error = new Win32Exception(code).Message;
            return false;
        }

        using var safeHandle = new SafeProcessHandle(handle, ownsHandle: true);
        var capacity = 32_768;
        var buffer = new StringBuilder(capacity);
        var size = capacity;
        if (QueryFullProcessImageName(safeHandle, 0, buffer, ref size))
        {
            path = buffer.ToString(0, size);
            return !string.IsNullOrWhiteSpace(path);
        }

        var queryCode = Marshal.GetLastWin32Error();
        error = new Win32Exception(queryCode).Message;
        return false;
    }

    public static (string? Description, string? CompanyName, string? FileVersion, string? Error) ReadVersionInfo(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return (null, null, null, null);
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            return (
                NullIfWhitespace(info.FileDescription),
                NullIfWhitespace(info.CompanyName),
                NullIfWhitespace(info.FileVersion),
                null);
        }
        catch (Exception ex)
        {
            return (null, null, null, ex.Message);
        }
    }

    public static void TryEnrichBasicInfo(Process process, out int sessionId, out DateTimeOffset? startTimeUtc, out string? error)
    {
        sessionId = -1;
        startTimeUtc = null;
        error = null;
        try
        {
            sessionId = process.SessionId;
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }

        try
        {
            startTimeUtc = process.StartTime.ToUniversalTime();
        }
        catch
        {
            // Start time may be unavailable for protected processes; unknown is honest.
        }
    }

    private static string? NullIfWhitespace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
