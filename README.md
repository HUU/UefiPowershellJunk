# PowerShell UEFI Control

This PowerShell module allows for the control of global UEFI variables from the operating system.  All commands require elevation to complete successfully.

_All cmdlets use nouns prefixed with "Uefi" for ease of auto-completion_

# Getting Started

```PowerShell
Import-Module .\Uefi.psm1
Get-Command -Module Uefi
```

# Accessing Raw variables

The lowest level cmdlets allow for access to the raw byte streams returned by the firmware.  These should be used with care unless you know the proper payload formats.

```PowerShell
Get-UefiVariable [-Name] <string>
Set-UefiVariable [-Name] <string> -Value <byte[]>
Remove-UefiVariable [-Name] <string>
```

# Boot Option Control

Extra cmdlets are provided which understand the format of the various `Boot` variables UEFI maintains.

### Listing Boot Options in Order
```PowerShell
Get-UefiBootOrder
```

### Retrieving a Specific Boot Option by Name
```PowerShell
Get-UefiBootOption Boot000D
```

### Retrieving a Specific Boot Option by Order
```PowerShell
Get-UefiBootOption 2
```

### Remove a Boot Option
```PowerShell
Get-UefiBootOption 2 | Remove-UefiBootOption
```

### Find and Remove a Boot Option by Description
```PowerShell
Get-UefiBootOrder | Get-UefiBootOption | ? { $_.Description.contains("Network Boot")} | Remove-UefiBootOption
```

# OS Indications

UEFI supports "OS Indications" which are bit masks passed between the OS and the firmware for the purpose of requesting certain operations after the next reboot.  An example is requesting that the next boot goes to UEFI setup instead of through the normal boot order.

Note that not all vendors support the full range of indications specified by the UEFI spec.  These operations will fail when attempting to modifty unsupported indications.  You can explicitly check the suppported indications with `Get-UefiOsIndicationSupported`.

```PowerShell
Enable-UefiOsIndication [-BootToFWUI] [-StartOsRecovery] [-StartPlatformRecovery]
Disable-UefiOsIndication [-BootToFWUI] [-StartOsRecovery] [-StartPlatformRecovery]
Get-UefiOsIndication
Get-UefiOsIndicationSupported
```