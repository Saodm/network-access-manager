using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NetworkAccessManager.Core.Native;

internal static class SignatureNative
{
    private const int WtdUiNone = 2;
    private const int WtdRevokeNone = 0;
    private const int WtdChoiceFile = 1;
    private const int WtdStateActionIgnore = 0;
    private const int WtdCacheOnlyUrlRetrieval = 0x00001000;
    private const int WtdRevocationCheckNone = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public int CbStruct;
        public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public int CbStruct;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public int UiChoice;
        public int RevocationChecks;
        public int UnionChoice;
        public IntPtr FileInfo;
        public int StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public int ProviderFlags;
        public int UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, IntPtr actionId, IntPtr trustData);

    public static (uint Result, string? Publisher) Verify(string filePath)
    {
        IntPtr actionIdPtr = IntPtr.Zero;
        IntPtr fileInfoPtr = IntPtr.Zero;
        IntPtr dataPtr = IntPtr.Zero;
        try
        {
            var actionId = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            actionIdPtr = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(actionId, actionIdPtr, false);

            var fileInfo = new WinTrustFileInfo
            {
                CbStruct = Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = filePath,
                FileHandle = IntPtr.Zero,
                KnownSubject = IntPtr.Zero
            };
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WinTrustData
            {
                CbStruct = Marshal.SizeOf<WinTrustData>(),
                PolicyCallbackData = IntPtr.Zero,
                SipClientData = IntPtr.Zero,
                UiChoice = WtdUiNone,
                RevocationChecks = WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                FileInfo = fileInfoPtr,
                StateAction = WtdStateActionIgnore,
                StateData = IntPtr.Zero,
                UrlReference = IntPtr.Zero,
                ProviderFlags = WtdCacheOnlyUrlRetrieval | WtdRevocationCheckNone,
                UiContext = 0,
                SignatureSettings = IntPtr.Zero
            };
            dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(data, dataPtr, false);

            var result = WinVerifyTrust(IntPtr.Zero, actionIdPtr, dataPtr);
            string? publisher = null;
            if (result == 0)
            {
                try
                {
#pragma warning disable SYSLIB0057
                    using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
                    publisher = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                }
                catch
                {
                    publisher = null;
                }
            }

            return (result, publisher);
        }
        finally
        {
            if (dataPtr != IntPtr.Zero)
            {
                try { Marshal.DestroyStructure<WinTrustData>(dataPtr); } catch { }
                Marshal.FreeHGlobal(dataPtr);
            }
            if (fileInfoPtr != IntPtr.Zero)
            {
                try { Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr); } catch { }
                Marshal.FreeHGlobal(fileInfoPtr);
            }
            if (actionIdPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(actionIdPtr);
        }
    }
}
