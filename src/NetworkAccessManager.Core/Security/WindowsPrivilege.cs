using System.Security.Principal;

namespace NetworkAccessManager.Core.Security;

public static class WindowsPrivilege
{
    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            if (identity.User is not null &&
                identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid))
                return true;
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
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
