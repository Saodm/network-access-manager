using System.Runtime.InteropServices;
using System.Security.Principal;

namespace NetworkAccessManager.Core.Security;

public static class WindowsPrivilege
{
    private const uint TokenQuery = 0x0008;
    private const int TokenElevation = 20;

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenElevationInfo
    {
        public int TokenIsElevated;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        out TokenElevationInfo tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>
    /// Returns true only when the current process token is actually elevated
    /// (or the process is LocalSystem). Membership in the Administrators group
    /// alone is not enough: a normally launched administrator process has a
    /// filtered token and cannot change firewall policy until UAC elevates it.
    /// This uses TokenElevation instead of WindowsPrincipal.IsInRole because
    /// group enrollment and elevation are different questions.
    /// </summary>
    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            if (identity.User is not null &&
                identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid))
                return true;

            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out var token))
                return false;
            try
            {
                if (!GetTokenInformation(
                        token,
                        TokenElevation,
                        out var elevation,
                        Marshal.SizeOf<TokenElevationInfo>(),
                        out _))
                    return false;
                return elevation.TokenIsElevated != 0;
            }
            finally
            {
                CloseHandle(token);
            }
        }
        catch
        {
            return false;
        }
    }

    public static string CurrentUserSid()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            return identity.User?.Value ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    public static string CurrentUserName()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            return identity.Name ?? Environment.UserName;
        }
        catch
        {
            return Environment.UserName;
        }
    }

    public static string PrivilegeText(bool isElevated) => isElevated
        ? "已取得管理员权限"
        : "普通权限（修改规则时请求 UAC）";
}
