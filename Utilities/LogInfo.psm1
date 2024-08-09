Function Start-LogAuditSetup
{
	param (
		[Parameter(Mandatory = $False)]
        [ValidateSet("JSON","Array")]
		[string]$OutputType="Array",
        [Parameter(Mandatory = $False)]
        [Array]$OtherLogs
)
$Logs = @("Application","System","Security")

$AppLogs - @()
$AppLogs = @(
    New-Object psobject -property @{
        Name = "RDSGateway"
        Role = "RDS-Gateway"
        DDTag = ""
        Type = "Detect"
        LogStringArray = @("*Microsoft-Windows-TerminalServices-Gateway*")
    }
    New-Object psobject -property @{
        Name = "IIS"
        Role = "Web-WebServer"
        DDTag = ""
        Type = "Detect"
        LogStringArray = @("*IIS-Configuration*","*IIS-Logging*","*HttpLog*","*HttpService*")
    }
    New-Object psobject -property @{
        Name = "DNS"
        Role = "DNS"
        DDTag = ""
        Type = "Detect"
        LogStringArray = @("DNS Server","*Microsoft-Windows-DNS-Server*")
    }
    New-Object psobject -property @{
        Name = "Active Directory"
        Role = "AD-Domain-Services"
        DDTag = ""
        Type = "Detect"
        LogStringArray = @("Directory Service","DFS Replication")
    }
    New-Object psobject -property @{
        Name = "Failover Clustering"
        Role = "Failover-Clustering"
        DDTag = ""
        Type = "Detect"
        LogStringArray = @("*FailoverClustering*")
    }
    New-Object psobject -property @{
        Name = "Remote Desktop Services"
        Role = "RDS-RD-Server"
        DDTag = ""
        Type = "Detect"
        LogStringArray = @("*Microsoft-Windows-RemoteApp and Desktop Connections*",
            "*Microsoft-Windows-RemoteDesktopServices-SessionServices*",
            "*Microsoft-Windows-TerminalServices-LocalSessionManager*",
            "*Microsoft-Windows-TerminalServices-RemoteConnectionManager*",
            "*Microsoft-Windows-TerminalServices-SessionBroker-Client*"
        )
    }
    New-Object psobject -property @{
        Name = "Connection Broker"
        Role = "RDS-Connection-Broker"
        DDTag = ""
        Type = "Detect"
        LogStringArray = @("*Microsoft-Windows-TerminalServices-SessionBroker*"
        )
    }
    New-Object psobject -property @{
        Name = "DFS Replication"
        Role = "FS-DFS-Replication"
        DDTag = ""
        Type = "Detect"
        LogStringArray = @("DFS Replication")
    }
    #New-Object psobject -property @{  #Example of a Custom Search
    #    Name = "SQL Server"
    #    Role = "if((Test-Path 'HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL') -eq 'True' )"
    #    Type = "CustomSearch"
    #    LogStringArray = @("")
    #}

)

$InstalledFeatures = Get-WindowsFeature | Where-Object{$_.InstallState -eq "Installed"}

foreach ($AppLog in $AppLogs){ #}

    ##Add All the defaults
    if($AppLog.Type -eq 'Default')
    {
        $Role=$AppLog.Name
        $AppString += $Role
    }

    ##Add any Parameter Advanced Options
    if($AppLog.Type -eq 'Advanced' -and $AdvancedListArray -contains $AppLog.Name)
    {
        $Role=$AppLog.Name
        $AppString += $Role
    }

    ##Add all Detected Roles
    if($AppLog.Type -eq "Detect")
    {
            if($InstalledFeatures.Name -contains $AppLog.Role) 
            {
                $Role=$AppLog.Name
                $AppString += $Role
            }
    }

    ##Add all CustomSearch Roles
    if($AppLog.Type -eq 'CustomSearch')
    {
        $Role=$AppLog.Name
        $Search=$AppLog.Role
        [string]$SearchString = $Search+'{[boolean]$True}else{[boolean]$False}'
        $TestResults = (Invoke-Expression $SearchString)
        
        #Write-host "$SearchString - $TestResults"
        if($TestResults -eq $True)
        {
            $AppString += $Role
        }
    }

}

if(
    (Get-WindowsFeature -Name "RDS-Gateway").Installed -eq $True){
        $GWLog = $True

}

$LogInfo =  [System.Collections.ArrayList]@()

foreach($Log in $Logs){
    ##Event Information
    $Events = Get-EventLog -LogName $log 

    $FirstEvent = $Events | Sort-Object TimeGenerated | Select-Object -First 1
    $LastEvent = $Events | Sort-Object TimeGenerated -Descending | Select-Object -First 1
    $Days = ($LastEvent.TimeGenerated - $FirstEvent.TimeGenerated).TotalHours/24

    ##Event Log Setup Info
    $EVInfo = get-winevent -ListLog $log  |Select MaximumSizeInBytes, FileSize, IsLogFull, OldestRecordNumber, IsEnabled, LogMode

    $MBperDay = ($EVInfo.FileSize / $Days)/1mb
    $Row =  [PsCustomObject]@{

        LogName = $Log
        Days = $Days
        CurrentSizeMB = $EVInfo.FileSize/1mb
        LogFull = $EVInfo.IsLogFull
        LogMode = $EVInfo.LogMode
        LogMaxSizeMB = $EVInfo.MaximumSizeInBytes/1mb
        MBperDay = $MBperDay
    }
    [void]$LogInfo.add($row)
   
}


if($GWLog -eq $True){
    $GWLogName = "*Microsoft-Windows-TerminalServices-Gateway*"
    $Logs = Get-WinEvent -ListLog $GWLogName
    foreach ($Log in $Logs){ #}
        $Events = Get-WinEvent -LogName $Log.LogName
        
        $FirstEvent = $Events | Sort-Object TimeCreated | Select-Object -First 1
        $LastEvent = $Events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $Days = ($LastEvent.TimeCreated - $FirstEvent.TimeCreated).TotalHours/24
    

        $EVInfo = get-winevent -ListLog $log.Logname  |Select MaximumSizeInBytes, FileSize, IsLogFull, OldestRecordNumber, IsEnabled, LogMode
        $LogName = $Log.Logname
        $MBperDay = ($EVInfo.FileSize / $Days)/1mb
        $Row =  [PsCustomObject]@{

        
        LogName = $LogName
        Days = $Days
        CurrentSizeMB = $EVInfo.FileSize/1mb
        LogFull = $EVInfo.IsLogFull
        LogMode = $EVInfo.LogMode
        LogMaxSizeMB = $EVInfo.MaximumSizeInBytes/1mb
        MBperDay = $MBperDay
    }
    [void]$LogInfo.add($row)
    }
}

if($OutputType -eq "JSON"){
    Return $LogInfo | ConvertTo-Json
}
IF($OutputType -eq "Array"){
    Return $LogInfo
}

}

Export-ModuleMember -function Start-LogAudit