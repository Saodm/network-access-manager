using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NetworkAccessManager.Core.Native;

public sealed class ServiceEnumerationResult
{
    public IReadOnlyDictionary<int, IReadOnlyList<Models.ServiceInstance>> ServicesByProcess { get; init; } =
        new Dictionary<int, IReadOnlyList<Models.ServiceInstance>>();
    public string? Error { get; init; }
    public int RunningServiceCount { get; init; }
}

internal static class ServiceNative
{
    private const uint ScManagerEnumerateService = 0x0004;
    private const int ScEnumProcessInfo = 0;
    private const uint ServiceWin32 = 0x00000030;
    private const uint ServiceStateAll = 0x00000003;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ErrorMoreData = 234;
    private const uint NoError = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public ServiceStatusProcess ServiceStatus;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusEx(
        IntPtr scManager,
        int infoLevel,
        uint serviceType,
        uint serviceState,
        IntPtr services,
        int bufferSize,
        out int bytesNeeded,
        out int servicesReturned,
        ref int resumeHandle,
        string? groupName);

    public static ServiceEnumerationResult Enumerate()
    {
        var scm = IntPtr.Zero;
        try
        {
            scm = OpenSCManager(null, null, ScManagerEnumerateService);
            if (scm == IntPtr.Zero)
                return new ServiceEnumerationResult { Error = new Win32Exception(Marshal.GetLastWin32Error()).Message };

            var resume = 0;
            var initial = EnumServicesStatusEx(
                scm, ScEnumProcessInfo, ServiceWin32, ServiceStateAll,
                IntPtr.Zero, 0, out var needed, out _, ref resume, null);
            var initialCode = (uint)Marshal.GetLastWin32Error();
            if (!initial && initialCode != ErrorInsufficientBuffer && initialCode != ErrorMoreData)
                return new ServiceEnumerationResult { Error = new Win32Exception((int)initialCode).Message };

            var bufferSize = Math.Max(needed + 16 * 1024, 64 * 1024);
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var buffer = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    resume = 0;
                    var ok = EnumServicesStatusEx(
                        scm, ScEnumProcessInfo, ServiceWin32, ServiceStateAll,
                        buffer, bufferSize, out needed, out var count, ref resume, null);
                    if (!ok)
                    {
                        var error = (uint)Marshal.GetLastWin32Error();
                        if (error == ErrorMoreData || error == ErrorInsufficientBuffer)
                        {
                            bufferSize = Math.Max(needed + 16 * 1024, bufferSize * 2);
                            continue;
                        }
                        return new ServiceEnumerationResult { Error = new Win32Exception((int)error).Message };
                    }

                    var map = new Dictionary<int, List<Models.ServiceInstance>>();
                    var stride = Marshal.SizeOf<EnumServiceStatusProcess>();
                    for (var i = 0; i < count; i++)
                    {
                        var ptr = IntPtr.Add(buffer, i * stride);
                        var entry = Marshal.PtrToStructure<EnumServiceStatusProcess>(ptr);
                        var serviceName = Marshal.PtrToStringUni(entry.ServiceName) ?? string.Empty;
                        var displayName = Marshal.PtrToStringUni(entry.DisplayName) ?? serviceName;
                        var pid = (int)entry.ServiceStatus.ProcessId;
                        var state = MapState(entry.ServiceStatus.CurrentState);
                        if (pid <= 0) continue;
                        if (!map.TryGetValue(pid, out var list))
                        {
                            list = new List<Models.ServiceInstance>();
                            map[pid] = list;
                        }
                        list.Add(new Models.ServiceInstance
                        {
                            Name = serviceName,
                            DisplayName = displayName,
                            State = state,
                            ProcessId = pid
                        });
                    }

                    var final = map.ToDictionary(
                        pair => pair.Key,
                        pair => (IReadOnlyList<Models.ServiceInstance>)pair.Value
                            .OrderBy(s => s.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                            .ToList());
                    return new ServiceEnumerationResult
                    {
                        ServicesByProcess = final,
                        RunningServiceCount = final.Values.Sum(v => v.Count)
                    };
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return new ServiceEnumerationResult { Error = "服务列表在读取过程中持续变化，无法取得一致快照。" };
        }
        catch (Exception ex)
        {
            return new ServiceEnumerationResult { Error = ex.Message };
        }
        finally
        {
            if (scm != IntPtr.Zero)
                CloseServiceHandle(scm);
        }
    }

    private static string MapState(uint state) => state switch
    {
        1 => "STOPPED",
        2 => "START_PENDING",
        3 => "STOP_PENDING",
        4 => "RUNNING",
        5 => "CONTINUE_PENDING",
        6 => "PAUSE_PENDING",
        7 => "PAUSED",
        _ => $"UNKNOWN({state})"
    };
}
