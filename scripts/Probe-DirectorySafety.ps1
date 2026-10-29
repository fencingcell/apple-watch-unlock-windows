# AGPL-3.0-only. Directory admission helpers; no service or machine configuration.
# Win32 CreateDirectoryW installs the descriptor atomically, and unlike the .NET
# convenience method fails if anything already occupies the requested name.
if (-not ('WatchLoginProbe.DirectorySafety' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace WatchLoginProbe {
    public static class DirectorySafety {
        [StructLayout(LayoutKind.Sequential)]
        struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int InheritHandle; }
        [StructLayout(LayoutKind.Sequential)]
        struct FileTime { public uint Low, High; }
        [StructLayout(LayoutKind.Sequential)]
        struct FileInformation {
            public uint Attributes; public FileTime Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct TokenPrivileges { public uint Count; public uint LuidLow; public int LuidHigh; public uint Attributes; }
        [DllImport("advapi32.dll",SetLastError=true)]
        static extern bool OpenProcessToken(IntPtr process,uint access,out SafeFileHandle token);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        static extern bool LookupPrivilegeValueW(string system,string name,out long luid);
        [DllImport("advapi32.dll",SetLastError=true)]
        static extern bool AdjustTokenPrivileges(SafeFileHandle token,bool disable,ref TokenPrivileges state,uint size,out TokenPrivileges previous,out uint length);
        static readonly object PrivilegeLock=new object();
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text,uint revision,out IntPtr descriptor,out uint length);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool CreateDirectoryW(string path,ref SecurityAttributes attributes);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInformation information);
        public static void CreateExclusive(string path,string sddl) {
            IntPtr descriptor; uint size;
            if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,out descriptor,out size))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"Invalid directory security descriptor");
            try {
                var attributes=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=descriptor,InheritHandle=0 };
                if(!CreateDirectoryW(path,ref attributes))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),"Exclusive directory creation failed; existing/raced paths are never adopted");
            } finally { LocalFree(descriptor); }
        }
        static SafeFileHandle PinCore(string path) {
            // OPEN_EXISTING, BACKUP_SEMANTICS, OPEN_REPARSE_POINT; omit SHARE_DELETE.
            // A real data access is required for Windows sharing checks. Metadata-only
            // access 0 does not block rename. Never enumerate or read private children.
            var handle=CreateFileW(path,1,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            if(handle.IsInvalid) {int code=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(code,"Cannot pin directory");}
            try {
                FileInformation info;
                if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if((info.Attributes&0x400)!=0 || (info.Attributes&0x10)==0) throw new InvalidOperationException("Expected a real directory, never a reparse point or file");
                return handle;
            } catch {handle.Dispose();throw;}
        }
        public static SafeFileHandle Pin(string path,bool backupAccess) {
            try {return PinCore(path);}
            catch(Win32Exception error) {if(!backupAccess || error.NativeErrorCode!=5) throw;}
            // An elevated administrator may inspect/pin a SYSTEM-only directory with
            // backup semantics. No DACL is changed; privilege is restored immediately.
            // https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
            lock(PrivilegeLock) {
                SafeFileHandle token;
                if(!OpenProcessToken(new IntPtr(-1),0x28,out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
                using(token) {
                    long luid;
                    if(!LookupPrivilegeValueW(null,"SeBackupPrivilege",out luid)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    var enabled=new TokenPrivileges {Count=1,LuidLow=(uint)luid,LuidHigh=(int)(luid>>32),Attributes=2};
                    TokenPrivileges previous; uint size;
                    if(!AdjustTokenPrivileges(token,false,ref enabled,16,out previous,out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    int error=Marshal.GetLastWin32Error();
                    if(error!=0) throw new Win32Exception(error,"Administrator backup privilege is unavailable; private directory was not opened");
                    SafeFileHandle pinned=null;
                    try {pinned=PinCore(path);return pinned;}
                    finally {
                        TokenPrivileges ignored; uint ignoredSize;
                        if(!AdjustTokenPrivileges(token,false,ref previous,16,out ignored,out ignoredSize) || Marshal.GetLastWin32Error()!=0) {
                            if(pinned!=null) pinned.Dispose();
                            throw new Win32Exception(Marshal.GetLastWin32Error(),"Could not restore backup privilege");
                        }
                    }
                }
            }
        }
    }
}
'@
}
function New-ProbeDirectoryExclusive([string]$Path,[string]$SecurityDescriptor) {
    [WatchLoginProbe.DirectorySafety]::CreateExclusive([IO.Path]::GetFullPath($Path),$SecurityDescriptor)
}
function Open-ProbePinnedDirectory([string]$Path,[switch]$BackupAccess) {
    [WatchLoginProbe.DirectorySafety]::Pin([IO.Path]::GetFullPath($Path),$BackupAccess.IsPresent)
}
function Add-ProbeAncestorPins([string]$Path,[Collections.Generic.List[IDisposable]]$Pins) {
    $ancestors=[Collections.Generic.List[string]]::new()
    $directory=[IO.Directory]::GetParent([IO.Path]::GetFullPath($Path))
    while($directory) {$ancestors.Add($directory.FullName);$directory=$directory.Parent}
    # Pin root first: later opens cannot be redirected by a renamed ancestor.
    for($i=$ancestors.Count-1;$i -ge 0;$i--) {$Pins.Add((Open-ProbePinnedDirectory $ancestors[$i]))}
}

