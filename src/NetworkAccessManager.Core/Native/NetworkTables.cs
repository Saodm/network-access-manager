using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NetworkAccessManager.Core.Native;

internal readonly record struct RawTcpRow(
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    int State,
    int OwningPid,
    AddressFamily AddressFamily);

internal readonly record struct RawUdpRow(
    IPAddress LocalAddress,
    int LocalPort,
    int OwningPid,
    AddressFamily AddressFamily);

internal static class NetworkTables
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ErrorNoData = 232;
    private const uint NoError = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    private delegate uint TableQuery(IntPtr buffer, ref int size);

    public static IReadOnlyList<RawTcpRow> GetIpv4TcpRows()
    {
        TableQuery query = (IntPtr buffer, ref int size) =>
            GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        var buffer = QueryTable(query);
        if (buffer == IntPtr.Zero) return Array.Empty<RawTcpRow>();
        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var list = new List<RawTcpRow>(count);
            for (var i = 0; i < count; i++)
            {
                var ptr = IntPtr.Add(buffer, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(ptr);
                list.Add(new RawTcpRow(
                    Ipv4(row.LocalAddr),
                    Port(row.LocalPort),
                    Ipv4(row.RemoteAddr),
                    Port(row.RemotePort),
                    (int)row.State,
                    (int)row.OwningPid,
                    AddressFamily.InterNetwork));
            }
            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static IReadOnlyList<RawTcpRow> GetIpv6TcpRows()
    {
        TableQuery query = (IntPtr buffer, ref int size) =>
            GetExtendedTcpTable(buffer, ref size, false, AfInet6, TcpTableOwnerPidAll, 0);
        var buffer = QueryTable(query);
        if (buffer == IntPtr.Zero) return Array.Empty<RawTcpRow>();
        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
            var list = new List<RawTcpRow>(count);
            for (var i = 0; i < count; i++)
            {
                var ptr = IntPtr.Add(buffer, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(ptr);
                list.Add(new RawTcpRow(
                    Ipv6(row.LocalAddr, row.LocalScopeId),
                    Port(row.LocalPort),
                    Ipv6(row.RemoteAddr, row.RemoteScopeId),
                    Port(row.RemotePort),
                    (int)row.State,
                    (int)row.OwningPid,
                    AddressFamily.InterNetworkV6));
            }
            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static IReadOnlyList<RawUdpRow> GetIpv4UdpRows()
    {
        TableQuery query = (IntPtr buffer, ref int size) =>
            GetExtendedUdpTable(buffer, ref size, false, AfInet, UdpTableOwnerPid, 0);
        var buffer = QueryTable(query);
        if (buffer == IntPtr.Zero) return Array.Empty<RawUdpRow>();
        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
            var list = new List<RawUdpRow>(count);
            for (var i = 0; i < count; i++)
            {
                var ptr = IntPtr.Add(buffer, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(ptr);
                list.Add(new RawUdpRow(
                    Ipv4(row.LocalAddr),
                    Port(row.LocalPort),
                    (int)row.OwningPid,
                    AddressFamily.InterNetwork));
            }
            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static IReadOnlyList<RawUdpRow> GetIpv6UdpRows()
    {
        TableQuery query = (IntPtr buffer, ref int size) =>
            GetExtendedUdpTable(buffer, ref size, false, AfInet6, UdpTableOwnerPid, 0);
        var buffer = QueryTable(query);
        if (buffer == IntPtr.Zero) return Array.Empty<RawUdpRow>();
        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibUdp6RowOwnerPid>();
            var list = new List<RawUdpRow>(count);
            for (var i = 0; i < count; i++)
            {
                var ptr = IntPtr.Add(buffer, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MibUdp6RowOwnerPid>(ptr);
                list.Add(new RawUdpRow(
                    Ipv6(row.LocalAddr, row.LocalScopeId),
                    Port(row.LocalPort),
                    (int)row.OwningPid,
                    AddressFamily.InterNetworkV6));
            }
            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntPtr QueryTable(TableQuery query)
    {
        var size = 0;
        var result = query(IntPtr.Zero, ref size);
        if (result == ErrorNoData) return IntPtr.Zero;
        if (result != NoError && result != ErrorInsufficientBuffer)
            throw new Win32Exception((int)result, $"读取网络表失败（Win32 错误 {result}）。");
        if (size <= 0) return IntPtr.Zero;

        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            var allocatedSize = size;
            result = query(buffer, ref allocatedSize);
            if (result == NoError)
                return buffer;
            Marshal.FreeHGlobal(buffer);
            if (result == ErrorNoData)
                return IntPtr.Zero;
            if (result == ErrorInsufficientBuffer)
            {
                size = Math.Max(allocatedSize, size * 2);
                continue;
            }

            throw new Win32Exception((int)result, $"读取网络表失败（Win32 错误 {result}）。");
        }

        throw new Win32Exception((int)ErrorInsufficientBuffer, "网络表在读取过程中持续增长，无法取得一致快照。");
    }

    private static IPAddress Ipv4(uint value) => new(BitConverter.GetBytes(value));

    private static IPAddress Ipv6(byte[]? bytes, uint scopeId)
    {
        var addressBytes = bytes is { Length: 16 } ? bytes : new byte[16];
        return new IPAddress(addressBytes, scopeId);
    }

    private static int Port(uint portDword) =>
        BinaryPrimitives.ReverseEndianness((ushort)(portDword & 0xFFFF));

    public static string TcpStateText(int state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"UNKNOWN({state})"
    };
}
