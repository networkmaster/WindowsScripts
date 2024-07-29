#requires -version 2

<#
A horribly written, kludged together script that takes an input of a computer name and spits out the last installed updates and the lasboot time. 

It is a compilation of different scripts pulled together - for those that wrote the originals, all credit to you. I claim no ownership to those parts of the code. 

C:\Scripts\Invoke-UpdateAndUptimeCheck.ps1 -ComputerName YOURPC

### REPORT FOR YOURPC ###

Installed updates in the last 90 days only:

ComputerName HotfixID  Description     HotfixTitle InstalledOn
------------ --------  -----------     ----------- -----------
YOURPC      KB5039343 Security Update NOT INDEXED 15/06/2024 12:00:00 AM
YOURPC      KB5040571 Security Update NOT INDEXED 19/07/2024 12:00:00 AM
YOURPC      KB5039889 Update          NOT INDEXED 19/07/2024 12:00:00 AM
YOURPC      KB5040437 Security Update NOT INDEXED 19/07/2024 12:00:00 AM


OS is: Microsoft Windows Server 2022 Standard 64-bit - Build 10.0.20348
Uptime check: 10 d 15 h 42 m 42 s
Pending Reboot Check: This device is not pending a reboot
Last Update Check: The last installed update was 07/19/2024 00:00:00


You will also need a CSV for the updates. A sample is in this repo. If the update isn't in the Repo it will say "Not indexed" 
Just google the KB and add it to the CSV for it to show. 


.SYNOPSIS
Outputs the last bootup time and uptime for one or more computers.

.DESCRIPTION
Outputs the last bootup time and uptime for one or more computers.

.PARAMETER ComputerName
One or more computer names. The default is the current computer. Wildcards are not supported.

.PARAMETER Credential
Specifies credentials that have permission to connect to the remote computer. This parameter is ignored for the current computer.

.OUTPUTS
PSObjects containing the computer name, the last bootup time, and the uptime.
#>

[CmdletBinding()]
param(
  [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    $ComputerName,
  [System.Management.Automation.PSCredential]
    $Credential
)

begin {
  function Out-Object {
    param(
      [System.Collections.Hashtable[]] $hashData
    )
    $order = @()
    $result = @{}
    $hashData | ForEach-Object {
      $order += ($_.Keys -as [Array])[0]
      $result += $_
    }
    New-Object PSObject -Property $result | Select-Object $order
  }

  function Format-TimeSpan {
    process {
      "{0:00} d {1:00} h {2:00} m {3:00} s" -f $_.Days,$_.Hours,$_.Minutes,$_.Seconds
    }
  }
  function Format-TimeSpanDays {
    process {
      "{0:00}" -f $_.Days
    }
  }

  function Get-Uptime {
    param(
      $computerName,
      $credential
    )
    # In case pipeline input contains ComputerName property
    if ( $computerName.ComputerName ) {
      $computerName = $computerName.ComputerName
    }
    if ( (-not $computerName) -or ($computerName -eq ".") ) {
      $computerName = [Net.Dns]::GetHostName()
    }
    $params = @{
      "Class" = "Win32_OperatingSystem"
      "ComputerName" = $computerName
      "Namespace" = "root\CIMV2"
    }
    if ( $credential ) {
      # Ignore -Credential for current computer
      if ( $computerName -ne [Net.Dns]::GetHostName() ) {
        $params.Add("Credential", $credential)
      }
    }
    try {
      $wmiOS = Get-WmiObject @params -ErrorAction Stop
    }
    catch {
      Write-Error -Exception (New-Object $_.Exception.GetType().FullName `
        ("Cannot connect to the computer '$computerName' due to the following error: '$($_.Exception.Message)'",
        $_.Exception))
      return
    }
    $lastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($wmiOS.LastBootUpTime)
    Out-Object `
      @{"ComputerName" = $computerName},
      @{"LastBootTime" = $lastBootTime},
      @{"Uptime"       = (Get-Date) - $lastBootTime | Format-TimeSpan}
      @{"UptimeInDays" = (Get-Date) - $lastBootTime | Format-TimeSpanDays}
  }
  function Get-HotfixInfo {
    param (
        $computerName
    )
    $ThisHotfixInfo = Get-HotFix -ComputerName $computerName
    return $ThisHotfixInfo
  }
  function Format-HotfixInfo {
    param (
        $RawHotfixData
    )
    $UpdateList = Import-CSV "\\a\path\to\a\UpdateList.csv"
    $FilteredHotfixes = $RawHotfixData | Where-Object {$_.InstalledOn -gt ((Get-Date).AddDays(-90))} | Select-Object -Property PSComputerName, Description, HotFixID, InstalledOn
    [System.Collections.ArrayList]$FormattedHotfixes = @()

    foreach ($Hotfix in $FilteredHotfixes){
        $UpdateInfo = $UpdateList | Where-Object {$_.KB -eq $Hotfix.HotFixID}
        If($null -eq $UpdateInfo){
            $HotfixTitle = "NOT INDEXED - Plz Google and add to CSV "
        }else{
            $HotfixTitle = $UpdateInfo.Description
        }
        
        $ThisHotfix = [PsCustomObject]@{
            ComputerName  = $Hotfix.PSComputerName
            HotfixID    = $Hotfix.HotfixID
            Description = $Hotfix.Description
            HotfixTitle = $HotfixTitle
            InstalledOn = $Hotfix.InstalledOn
        }
        $FormattedHotfixes.Add($ThisHotfix) | out-null
        Remove-Variable -name UpdateInfo
        Remove-Variable -name HotfixTitle
    }
    return $FormattedHotfixes
}  
function Get-PendingRebootStatus {
    param (
        $ComputerName
    )
    Try {
        $PendingReboot = $false

        $HKLM = [UInt32] "0x80000002"
        $WMI_Reg = [WMIClass] "\\$ComputerName\root\default:StdRegProv"

        if ($WMI_Reg) {
            if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') {$PendingReboot = $true}
            if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true}

            #Checking for SCCM namespace
            $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $ComputerName -ErrorAction Ignore
            if ($SCCM_Namespace) {
                if (([WmiClass]"\$ComputerName\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq $true) {$PendingReboot = $true}
            }

            $RebootResult = [PSCustomObject]@{
                ComputerName  = $ComputerName.ToUpper()
                PendingReboot = $PendingReboot
            }
        }
    } catch {
        Write-Error $_.Exception.Message

    } finally {
        #Clearing Variables
        $null = $WMI_Reg
        $null = $SCCM_Namespace
    }
    return $RebootResult
}
function Get-OSDetails {
    param (
        $ComputerName
    )
	$OSDeets = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName | Select-Object PSComputerName, Caption, OSArchitecture, Version, BuildNumber
	$OSFormatted = "$($OSDeets.Caption) $($OSDeets.OSArchitecture) - Build $($OSDeets.Version)"
	return $OSFormatted
}
}

process {
  if ( $ComputerName ) {
    foreach ( $computerNameItem in $ComputerName ) {
      $ThisUptime = Get-Uptime $computerNameItem $Credential
      $ThisHotfixInfo = Get-HotfixInfo $ComputerName
      $PendingRebootStatus = Get-PendingRebootStatus -ComputerName $ComputerName
      $FormattedHotfixes = Format-HotfixInfo -RawHotfixData $ThisHotfixInfo
      if($null -eq $FormattedHotfixes){
        
      }else{
        $LastInstalledUpdate = $FormattedHotfixes[$FormattedHotfixes.Count - 1]
      }
      

      #Clear-Host
      write-host " "
      Write-host -ForegroundColor yellow "### REPORT FOR $ComputerName ###"
      write-host " "
      Write-Host -ForegroundColor yellow "Installed updates in the last 90 days only:"
     
      if($null -eq $FormattedHotfixes){
        write-host -ForegroundColor Red "ZOMGWTFBBQ - NO PATCHES FOUND INSTALLED IN THE LAST 90 DAYS!?!?!?!?!"
      }else{
        $FormattedHotFixes | Sort-Object InstalledOn | format-table -autosize
      }

	$ThisOSDetails = Get-OSDetails -ComputerName $ComputerName
    if($ThisOSDetails -like "*2003*" -or $ThisOSDetails -like "*2008*" -or $ThisOSDetails -like "*2012 SP2*"){
		$OSColour = "Red"
	}elseif($ThisOSDetails -like "*2012 R2*"){
		$OSColour = "Red"
	}elseif($ThisOSDetails -like "*2016*"){
		$OSColour = "Yellow"
	}elseif($ThisOSDetails -like "*2019*" -or $ThisOSDetails -like "*2022*"){
		$OSColour = "Green"
	}else{
		$OSColour = "white"
	}
	Write-Host -ForegroundColor $OSColour "OS is: $ThisOSDetails"

      if($ThisUptime.UptimeInDays -le "28"){
        $UTColour = "Green"
      }elseif ($ThisUptime.UptimeInDays -ge "29" -and $ThisUptime.UptimeInDays -le "45") {
        $UTColour = "Yellow"
      }elseif ($ThisUptime.UptimeInDays -ge "46") {
        $UTColour = "Red"
      }else{
        $UTColour = "Magenta"
      }
      Write-Host -ForegroundColor $UTColour "Uptime check:" $ThisUptime.uptime
      
      if($PendingRebootStatus.PendingReboot -eq $true){
        Write-Host -ForegroundColor red "Pending Reboot Check: THIS DEVICE ($Computername) HAS A PENDING REBOOT!"
      }else{
        write-host -ForegroundColor Green "Pending Reboot Check: This device is not pending a reboot"
      }
      if($null -eq $LastInstalledUpdate){
        write-host -ForegroundColor red "Last Update Check: This device has no recorded last update"
      }else{
        Write-Host -ForegroundColor green "Last Update Check: The last installed update was $($LastInstalledUpdate.InstalledOn)"
      }
      
      write-host " "
    }
  }else{
    $ThisUptime = Get-Uptime "."
    $ThisHotfixInfo = Get-HotfixInfo $ComputerName
    $FormattedHotfixes = Format-HotfixInfo -RawHotfixData $ThisHotfixInfo
    #Clear-Host
    write-host " "
    Write-host -ForegroundColor yellow "### REPORT FOR $ComputerName ###"
    write-host " "
    Write-Host -ForegroundColor yellow "Installed updates in the last 90 days only:"
   
    if($null -eq $FormattedHotfixes){
      write-host -ForegroundColor Red "ZOMGWTFBBQ - NO PATCHES FOUND INSTALLED IN THE LAST 90 DAYS!?!?!?!?!"
    }else{
      $FormattedHotFixes | Sort-Object InstalledOn | format-table -autosize
    }
	
	$ThisOSDetails = Get-OSDetails -ComputerName $ComputerName
    if($ThisOSDetails -like "*2003*" -or $ThisOSDetails -like "*2008*" -or $ThisOSDetails -like "*2012 SP2*"){
		$OSColour = "Red"
	}elseif($ThisOSDetails -like "*2012 R2*"){
		$OSColour = "Red"
	}elseif($ThisOSDetails -like "*2016*"){
		$OSColour = "Yellow"
	}elseif($ThisOSDetails -like "*2019*" -or $ThisOSDetails -like "*2022*"){
		$OSColour = "Green"
	}else{
		$OSColour = "white"
	}
	Write-Host -ForegroundColor $OSColour "OS is: $ThisOSDetails"
	
	
    if($ThisUptime.UptimeInDays -le "28"){
      $UTColour = "Green"
    }elseif ($ThisUptime.UptimeInDays -ge "29" -and $ThisUptime.UptimeInDays -le "45") {
      $UTColour = "Yellow"
    }elseif ($ThisUptime.UptimeInDays -ge "46") {
      $UTColour = "Red"
    }else{
      $UTColour = "Magenta"
    }
    Write-Host -ForegroundColor $UTColour "Current Uptime of $ComputerName :" $ThisUptime.uptime
    
    if($PendingRebootStatus.PendingReboot -eq $true){
      Write-Host -ForegroundColor red "THIS DEVICE ($Computername) HAS A PENDING REBOOT!"
    }else{
      write-host -ForegroundColor Green "This device is not pending a reboot"
    }
    write-host " "
  }
}
