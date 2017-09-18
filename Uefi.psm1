$references = @()
$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UefiControl
{
    [Flags]
    public enum Attributes : uint
    {
        Active          = 0x00000001,
        ForceReconnect  = 0x00000002,
        Hidden          = 0x00000008,
        Category        = 0x00001F00,
        Category_Boot   = 0x00000000,
        Category_App    = 0x00000100
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EFI_LOAD_OPTION
    {
        public Attributes Attributes;
        public UInt16 FilePathListLength;
        public string Description;
        public EFI_DEVICE_PATH_PROTOCOL[] FilePathList;
        public byte[] OptionalData;

        public override string ToString()
        {
            return Description + "\r\n" +
                    "\tFlags: " + Attributes + "\r\n" +
                    "\tDevice Paths: " + FilePathList.Length + "\r\n";
        }
    }

    public struct EFI_DEVICE_PATH_PROTOCOL
    {
        public byte Type;
        public byte SubType;
        public UInt16 Length;
        public byte[] Data;
    }

    [Flags]
    public enum OsIndications : ulong
    {
        BOOT_TO_FW_UI                   = 0x001,
        TIMESTAMP_REVOCATION            = 0x002,
        FILE_CAPSULE_DELIVERY_SUPPORTED = 0x004,
        FMP_CAPSULE_SUPPORTED           = 0x008,
        CAPSULE_RESULT_VAR_SUPPORTED    = 0x010,
        START_OS_RECOVERY               = 0x020,
        START_PLATFORM_RECOVERY         = 0x040
    }

    public class Uefi
    {
        public const string GLOBAL_BOOTORDER = "BootOrder";
        public const string GLOBAL_OSINDICATIONS = "OsIndications";
        public const string GLOBAL_OSINDICATIONSSUPPORTED = "OsIndicationsSupported";
        public const string PREFIX_BOOTOPTION = "Boot";

        public Uefi()
        {
            Native.AcquirePrivilege(Native.SE_SYSTEM_ENVIRONMENT_NAME);
        }

        private string ReadNullTerminatedWideString(BinaryReader reader)
        {
            using (MemoryStream unicodePassThrough = new MemoryStream())
            using (BinaryWriter unicodeWriter = new BinaryWriter(unicodePassThrough))
            using (StreamReader unicodeReader = new StreamReader(unicodePassThrough, Encoding.Unicode))
            {
                UInt16 raw;
                for (int i = 0; (raw = reader.ReadUInt16()) != 0 ; i += 2)
                {
                    unicodeWriter.Write(raw);
                }

                unicodeWriter.Flush();
                unicodePassThrough.Position = 0;
                return unicodeReader.ReadToEnd();
            }
        }

        private IEnumerable<EFI_DEVICE_PATH_PROTOCOL> ReadDevicePathProtocolUntil(BinaryReader reader, int maxBytesRead)
        {
            // this struct was designed by a fool
            int bytesRead = 0;
            while (bytesRead < maxBytesRead)
            {
                EFI_DEVICE_PATH_PROTOCOL devicePath;
                devicePath.Type = reader.ReadByte();
                devicePath.SubType = reader.ReadByte();
                devicePath.Length = reader.ReadUInt16();
                devicePath.Data = reader.ReadBytes(devicePath.Length - 4);

                bytesRead += 1 + 1 + 2 + devicePath.Length - 4;
                yield return devicePath;
            }
        }

        private string ToHexFixEndianness(byte[] source, int index, int length)
        {
            StringBuilder hex = new StringBuilder();
            for (int i = index + length - 1; i >= index; i--)
            {
                hex.Append(source[i].ToString("X2"));
            }
            return hex.ToString();
        }

        private void MarshalBootOption(string name, BinaryWriter stream)
        {
            if (name.StartsWith(PREFIX_BOOTOPTION))
            {
                name = name.Substring(PREFIX_BOOTOPTION.Length);
            }

            if (name.Length != 4) // expect 4 hex char because field is UInt16
            {
                throw new ArgumentOutOfRangeException("name");
            }

            for (int i = name.Length - 2; i >= 0; i -= 2)
            {
                stream.Write(Convert.ToByte(name.Substring(i, 2), 16));
            }
        }

        public EFI_LOAD_OPTION ParseBootVariable(byte[] data)
        {
            EFI_LOAD_OPTION loadOption;
            using (BinaryReader reader = new BinaryReader(new MemoryStream(data)))
            {
                loadOption.Attributes = (Attributes)reader.ReadUInt32();
                loadOption.FilePathListLength = reader.ReadUInt16();
                loadOption.Description = this.ReadNullTerminatedWideString(reader);
                loadOption.FilePathList = this.ReadDevicePathProtocolUntil(reader, loadOption.FilePathListLength).ToArray();
                loadOption.OptionalData = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));
            }

            return loadOption;
        }

        public void RemoveBootOption(string name)
        {
            bool found = false;
            using (MemoryStream buffer = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(buffer))
                {
                    foreach (string option in this.ReadBootOptions())
                    {
                        Console.WriteLine(option);
                        if (option.Equals(name))
                        {
                            found = true;
                        }
                        else
                        {
                            this.MarshalBootOption(option, writer);
                        }
                    }
                }

                if (!found)
                {
                    throw new ArgumentOutOfRangeException("Boot option not found");
                }
                else
                {
                    byte[] newValue = buffer.ToArray();
                    this.WriteVariable(GLOBAL_BOOTORDER, newValue);
                }
            }
        }

        public void WriteVariable(string name, byte[] data)
        {
            IntPtr buffer = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, buffer, data.Length);
                if (!Native.SetFirmwareEnvironmentVariable(name,
                    Native.EFI_GLOBAL_VARIABLE,
                    buffer,
                    (uint)data.Length))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public byte[] ReadVariable(string name)
        {
            IntPtr buffer = Marshal.AllocHGlobal(1024);
            try
            {
                uint written = Native.GetFirmwareEnvironmentVariable(name,
                                    Native.EFI_GLOBAL_VARIABLE,
                                    buffer,
                                    1024);
                int error = Marshal.GetLastWin32Error();
                if (error != (int)Native.Win32Error.ERROR_SUCCESS && written <= 0)
                {
                    throw new Win32Exception(error);
                }

                byte[] result = new byte[written];
                Marshal.Copy(buffer, result, 0, (int)written);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public IEnumerable<string> ReadBootOptions()
        {
            byte[] rawOrder = this.ReadVariable(GLOBAL_BOOTORDER);
            return this.ReadBootOptions(rawOrder);

        }

        public IEnumerable<string> ReadBootOptions(byte[] rawOrder)
        {
            if (rawOrder.Length % 2 != 0)
            {
                throw new DataMisalignedException("The " + GLOBAL_BOOTORDER + " contains extra bytes?");
            }

            for (int i = 0; i < rawOrder.Length; i += 2)
            {
                yield return PREFIX_BOOTOPTION + this.ToHexFixEndianness(rawOrder, i, 2);
            }
        }

        public OsIndications ReadOsIndications()
        {
            byte[] found;
            try
            {
                found = this.ReadVariable(GLOBAL_OSINDICATIONS);
            }
            catch (Win32Exception)
            {
                found = new byte[64];
            }
            return (OsIndications)BitConverter.ToUInt64(found, 0);
        }

        public OsIndications ReadOsIndicationsSupported()
        {
            return (OsIndications)BitConverter.ToUInt64(this.ReadVariable(GLOBAL_OSINDICATIONSSUPPORTED), 0);
        }

        public void SetOsIndications(OsIndications indications)
        {
            OsIndications notSupported;
            if ((notSupported = indications & this.ReadOsIndicationsSupported()) != indications)
            {
                throw new ArgumentOutOfRangeException("Requested unsupported indications: " + notSupported);
            }

            byte[] newValue = BitConverter.GetBytes((UInt64)indications);
            this.WriteVariable(GLOBAL_OSINDICATIONS, newValue);
        }
    }

    public class Native
    {
        public const string EFI_GLOBAL_VARIABLE = "{8BE4DF61-93CA-11d2-AA0D-00E098032B8C}";

        public enum Win32Error : uint
        {
            ERROR_SUCCESS = 0x0
        }

        private static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private static uint STANDARD_RIGHTS_READ = 0x00020000;
        private static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private static uint TOKEN_DUPLICATE = 0x0002;
        private static uint TOKEN_IMPERSONATE = 0x0004;
        private static uint TOKEN_QUERY = 0x0008;
        private static uint TOKEN_QUERY_SOURCE = 0x0010;
        private static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private static uint TOKEN_ADJUST_GROUPS = 0x0040;
        private static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private static uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        private static uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

        public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";

        public const string SE_AUDIT_NAME = "SeAuditPrivilege";

        public const string SE_BACKUP_NAME = "SeBackupPrivilege";

        public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";

        public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";

        public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";

        public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";

        public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";

        public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";

        public const string SE_DEBUG_NAME = "SeDebugPrivilege";

        public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";

        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";

        public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";

        public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";

        public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";

        public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";

        public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";

        public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";

        public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";

        public const string SE_RELABEL_NAME = "SeRelabelPrivilege";

        public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";

        public const string SE_RESTORE_NAME = "SeRestorePrivilege";

        public const string SE_SECURITY_NAME = "SeSecurityPrivilege";

        public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";

        public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";

        public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";

        public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";

        public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";

        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

        public const string SE_TCB_NAME = "SeTcbPrivilege";

        public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";

        public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";

        public const string SE_UNDOCK_NAME = "SeUndockPrivilege";

        public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
            UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName,
            out LUID lpLuid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern UInt32 GetFirmwareEnvironmentVariable(
            String lpName,
            String lpGuid,
            IntPtr pBuffer,
            UInt32 nSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool SetFirmwareEnvironmentVariable(
            String lpName,
            String lpGuid,
            IntPtr pBuffer,
            UInt32 nSize
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            UInt32 Zero,
            IntPtr Null1,
            IntPtr Null2);

        public static void AcquirePrivilege(string privilege)
        {
            IntPtr hToken;
            LUID luidSEValue;
            TOKEN_PRIVILEGES tkpPrivileges;

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                if (!LookupPrivilegeValue(null, privilege, out luidSEValue))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                tkpPrivileges.PrivilegeCount = 1;
                tkpPrivileges.Luid = luidSEValue;
                tkpPrivileges.Attributes = SE_PRIVILEGE_ENABLED;

                if (!AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                CloseHandle(hToken);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }
    }
}
'@

if (-not $global:UefiControlCompiled)
{
    Write-Verbose "Loading UEFI management p/invoke shim."
    Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies $references -ErrorAction Stop
    $global:UefiControlCompiled = $true
}
else
{
    Write-Warning "UEFI management class was already loaded.  If you made any changes, you will need to close and re-open PowerShell to successfully import the new module."
}

function Get-UefiVariable
{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )

    $uefi = New-Object UefiControl.Uefi
    $uefi.ReadVariable($Name)
}

function Set-UefiVariable
{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter(Position=1,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [byte[]] $Value
    )

    $uefi = New-Object UefiControl.Uefi
    $uefi.WriteVariable($Name, $Value);
}

function Get-UefiBootOrder
{
    [CmdletBinding()]
    Param(
    )

    $uefi = New-Object UefiControl.Uefi
    $uefi.ReadBootOptions() | ForEach-Object {
        Write-Output $_
    }
}

function Get-UefiBootOption
{
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true,ParameterSetName="Name",Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter(ParameterSetName="Ordinal",Mandatory=$true,Position=0)]
        [int] $Index
    )

    process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            "Name"
            {
                $option = $Name
            }
            "Ordinal"
            {
                $option = Get-UefiBootOrder | Select-Object -Skip $Index | Select-Object -First 1
            }
        }

        $uefi = New-Object UefiControl.Uefi
        $var = $uefi.ParseBootVariable($uefi.ReadVariable($option))
        Add-Member -InputObject $var -PassThru -Type NoteProperty -Name "Name" -Value $option
    }
}

function Remove-UefiVariable
{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )

    $uefi = New-Object UefiControl.Uefi
    $uefi.WriteVariable($Name, @())
}

function Remove-UefiBootOption
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )

    $uefi = New-Object UefiControl.Uefi
    $uefi.RemoveBootOption($Name)
}

function Enable-UefiOsIndication
{
    [CmdletBinding()]
    Param(
        [Parameter()]
        [switch] $BootToFWUI,

        [Parameter()]
        [switch] $StartOsRecovery,

        [Parameter()]
        [switch] $StartPlatformRecovery
    )

    $uefi = New-Object UefiControl.Uefi
    $indications = $uefi.ReadOsIndications()
    
    if ($StartOsRecovery)
    {
        $indications = $indications -bor [UefiControl.OsIndications]::START_OS_RECOVERY
    }
    if ($StartPlatformRecovery)
    {
        $indications = $indications -bor [UefiControl.OsIndications]::START_PLATFORM_RECOVERY
    }
    if ($BootToFWUI)
    {
        $indications = $indications -bor [UefiControl.OsIndications]::BOOT_TO_FW_UI
    }

    $uefi.SetOsIndications($indications)
}

function Get-UefiOsIndication
{
    [CmdletBinding()]
    Param(
    )

    $uefi = New-Object UefiControl.Uefi
    $uefi.ReadOsIndications()
}

function Get-UefiOsIndicationSupported
{
    [CmdletBinding()]
    Param(
    )

    $uefi = New-Object UefiControl.Uefi
    $uefi.ReadOsIndicationsSupported()
}

function Disable-UefiOsIndication
{
    [CmdletBinding()]
    Param(
        [Parameter()]
        [switch] $BootToFWUI,

        [Parameter()]
        [switch] $StartOsRecovery,

        [Parameter()]
        [switch] $StartPlatformRecovery
    )

    $uefi = New-Object UefiControl.Uefi
    $indications = $uefi.ReadOsIndications()
    
    if ($StartOsRecovery)
    {
        $indications = $indications -band (-bnot [UefiControl.OsIndications]::START_OS_RECOVERY)
    }
    if ($StartPlatformRecovery)
    {
        $indications = $indications -band (-bnot [UefiControl.OsIndications]::START_PLATFORM_RECOVERY)
    }
    if ($BootToFWUI)
    {
        $indications = $indications -band (-bnot [UefiControl.OsIndications]::BOOT_TO_FW_UI)
    }

    $uefi.SetOsIndications($indications)
}

Export-ModuleMember -Function Get-UefiVariable
Export-ModuleMember -Function Remove-UefiVariable
Export-ModuleMember -Function Set-UefiVariable
Export-ModuleMember -Function Get-UefiBootOrder
Export-ModuleMember -Function Get-UefiBootOption
Export-ModuleMember -Function Remove-UefiBootOption
Export-ModuleMember -Function Enable-UefiOsIndication
Export-ModuleMember -Function Disable-UefiOsIndication
Export-ModuleMember -Function Get-UefiOsIndication
Export-ModuleMember -Function Get-UefiOsIndicationSupported
