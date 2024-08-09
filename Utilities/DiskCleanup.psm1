function Clear-ASPNetCache {
    <#
        .SYNOPSIS
        This function is used to cleanup the ASP.Net temporary Cache files on an IIS Server
    
        
        .DESCRIPTION
        Suggested Output use in a script
        
    #>
    
        param (
            [Parameter(Mandatory=$False)]
            [boolean]$Now=$False,
            [Parameter(Mandatory=$False)]
            [string]$BusinessEnd=21,
            [Parameter(Mandatory=$False)]
            [Int]$Filter,
            [Parameter(Mandatory=$False)]
            [Int]$BusinessStart=04
        )
     #Script needs to invoke this first:
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    
        $ReturnData = @()
       
        #[int]$now = get-date -format HH
        
        
        if($Now -eq $false){
            do {
                [int]$now = get-date -format HH
                #$now++
                $now
                start-sleep -Seconds 3600
            } until ($now -ge $BusinessEnd -or $now -le $BusinessStart)
        

            $random =get-random -Minimum 120 -Maximum 3600

            write-host "RandomSleep $Random"
            Start-Sleep -Seconds $Random

            
            [int]$now = get-date -format HH
            if (
            $now -le $BusinessEnd -and $now -ge $BusinessStart
            ){
            write-host "BusinessHours" 
            break
            }
        }
        $Server = $Env:COMPUTERNAME
        iisreset /stop

        $Count = (Get-ChildItem "C:\Windows\Microsoft.NET\Framework*\v*\Temporary ASP.NET Files\root" -Recurse).Count
        write-host "Cleaning $Count Files"
        Get-ChildItem "C:\Windows\Microsoft.NET\Framework*\v*\Temporary ASP.NET Files\root" -Recurse | Remove-Item -Recurse

        iisreset /start
        
        $ReturnData  = [ordered]@{
            Machine = $Server
            Date = (get-date)
            FileCount = $count
        }
      
    
        Return $ReturnData
        #$files | ForEach-Object { $_; New-Item (Join-Path $Path (Split-Path $_)) -ItemType Directory -ea SilentlyContinue | Out-Null
        #    (New-Object System.Net.WebClient).DownloadFile($uri + "/" + $_ + "?" + $sas, (Join-Path $Path $_))
        # }
}

function Clear-DMPFiles () {
<#
        .SYNOPSIS
        This function is used to cleanup the system DMP Files from a system.
    
        
        .DESCRIPTION
        Suggested Output use in a script
        
    #>
    $ErrorActionPreference = 'SilentlyContinue'
        
    $Disks = get-volume |?{$_.DriveType -eq 'Fixed' -and $_.DriveLetter -ne $Null}
    $FileCount = 0
    $FileSize = 0   
    $Server = $Env:COMPUTERNAME
    foreach($Disk in $Disks){ #}
        $DriveLetter = $Disk.DriveLetter
        $FileCount = 0
        # Get users
        $users = Get-ChildItem -Path "$DriveLetter`:\Users" #| Where-Object Name -NotLike "_svc*"
        # Loop through users and delete the file
        foreach ($User in $users) { #}
            $dmppath = "$DriveLetter`:\users\"+$user.name+"\AppData\Local\CrashDumps"
        
            $Files = Get-ChildItem -Path $dmppath -filter *.dmp -Recurse #| Select -First 1
            $Files | Remove-Item -Force -Recurse #-verbose

            $FileCount = $Files.count + $FileCount
            $FileSize = ($Files.length | Measure-Object -sum).sum + $FileSize
        }
    }

    $Files = Get-ChildItem -Path "C:\Windows\memory.dmp"
    $Files | Remove-Item -Force
    $FileCount = $Files.count + $FileCount
    $FileSize =  ($Files.length | Measure-Object -sum).sum + $FileSize

    $Files = Get-ChildItem -Path "C:\Windows\LiveKernelReports" -filter *.dmp
    $Files | Remove-Item -Force
    $FileCount = $Files.count + $FileCount
    $FileSize =  ($Files.length | Measure-Object -sum).sum + $FileSize

    $FileSizeMB = [math]::round($FileSize/1mb,3)

    $ReturnData  = [ordered]@{
        Machine = $Server
        Date = (get-date)
        FileCount = $FileCount
        FileSizeMB = $FileSizeMB
    }

    Return $ReturnData


}

function Test-PendingReboot {
    #Adapted from https://gist.github.com/altrive/5329377
    #Based on <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542>
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($status -ne $null) -and $status.RebootPending) {
            return $true
        }
    }
    catch { }

    return $false
}

function Clear-WinSXS {
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER Now
Parameter description

.PARAMETER BusinessEnd
Parameter description

.PARAMETER BusinessStart
Parameter description

.PARAMETER LastUpdateCheckDays
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>

##ChangeLog
# Addes logic around Last Patch Installed and Rebooting stops and error feedback


    param (
            [Parameter(Mandatory=$False)]
            [boolean]$RunNow=$False,
            [Parameter(Mandatory=$False)]
            [string]$BusinessEnd=19,
            [Parameter(Mandatory=$False)]
            [Int]$BusinessStart=04,
            [Parameter(Mandatory=$False)]
            [Int]$LastUpdateCheckDays=6
    )

##Check Patches installed for days before cleanup
    $lastUpdate = Get-WmiObject -Query "SELECT * FROM Win32_QuickFixEngineering" | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if(!$LastUpdate){
        Write-Host "FAILED: Unable to query lastUpdate, stopping!"
        Break
    }
    $now = (get-Date)
    $1WeekAgo = $now.AddDays($LastUpdateCheckDays)
    $LastUpdateOn = $LastUpdate.InstalledOn

    if($LastUpdateOn -lt $1weekAgo){
        Write-Host "Last Patch Update: $LastUpdateOn."
        $Continue = $true
    }else{
        $Continue = $false
        Write-Host "FAILED: Cleanup can not start due to patches being installed less that 1 week
    Last Update:$LastUpdateOn" -BackgroundColor Red -ForegroundColor Black

    Write-Host "Last Windows Update Installed:"
    Write-Host "--------------------------------"
    Write-Host "Hotfix ID: $($lastUpdate.HotFixID)"
    Write-Host "Description: $($lastUpdate.Description)"
    Write-Host "Installed On: $($lastUpdate.InstalledOn)"
    Break
    }


$PendingReboot = Test-PendingReboot
if($PendingReboot -eq $true){
    Write-Host "FAILED: Pending Reboot: $PendingReboot"
    $Continue = $False
    Break
}

###Business Hours Wait
    if($RunNow -eq $false){
        do {
            [int]$now = get-date -format HH
            #$now++
            $now
            start-sleep -Seconds 3600
        } until ($now -ge $BusinessEnd -or $now -le $BusinessStart)
 
        $random =get-random -Minimum 120 -Maximum 300

        write-host "RandomSleep $Random"
        Start-Sleep -Seconds $Random
       
        [int]$now = get-date -format HH
        if (
        $now -le $BusinessEnd -and $now -ge $BusinessStart
        ){
        write-host "BusinessHours" 
        break
        }
    }

##Start Cleanup of WinSXS if no reboot pending and no updates in last $LastUpdateCheckDays

    if($Continue -eq $true){
        $CleanupAttrib = @(
            "/online"
            "/Cleanup-Image"
            "/StartComponentCleanup"
            "/ResetBase"
        )
        
        $drive = Get-Volume -DriveLetter C
        $predriveSizeGB = [math]::Round($drive.SizeRemaining / 1GB)  # Convert bytes to gigabytes and round to nearest whole number


        Try{
            $Process = Start-Process dism.exe -ArgumentList $CleanupAttrib -WindowStyle Hidden -PassThru
            Write-Host "WinSXS Cleanup Started:"(Get-Date)
            wRITE-hOST "Free:$predriveSizeGB GB"
            $ProcessID = $Process.ID

        } Catch {
            Write-Host "FAILED: DISM Cleanup Not Supported.  Cleanup Failed to Run."
        }
    }else{
        Write-Host "FAILED: WinSXS Cleanup Not Started."
        if($RecentUpdates -lt $LastUpdateCheckDays){
            Write-Host "Last Update (Days ago): $RecentUpdates"
            Break
        }
        if($PendingReboot -eq $true){
            Write-Host "FAILED: Pending Reboot: $PendingReboot"
            Break
        }
    }
    Do{$Status = Get-Process -Id $ProcessID -ErrorAction SilentlyContinue;Start-sleep -seconds 60}until (!$Status)
    $drive = Get-Volume -DriveLetter C
    $postdriveSizeGB = [math]::Round($drive.SizeRemaining / 1GB)  # Convert bytes to gigabytes and round to nearest whole number
    $ChangeGB = $postdriveSizeGB-$predriveSizeGB
    Write-Host "WinSXS Cleanup Finished:"(Get-Date)
    Write-Host "Free: $postdriveSizeGB"
    Write-Host "Saved:$ChangeGB GB"
}

function Clear-IISLogFiles {
    param (
        [Parameter(Mandatory=$False)]
        [int]$daysToKeep=8,
        [Parameter(Mandatory=$False)]
        [string]$LogDirectory="c:\inetpub\logs\LogFiles",
        [Parameter(Mandatory=$False)]
        [string]$RootPath="c:\temp",
        [Parameter(Mandatory=$False)]
        [string]$ArchiveFolderName="IISLogs",
        [Parameter(Mandatory=$False)]
        [int]$ArchivesKeepCount=4
    )
    # Define the number of days to keep logs before compressing
    #$daysToKeep = 30
    if(!(Test-Path $LogDirectory)){
        Write-Host "No Log Files Found.  Check Log Directory.  Stopping"
        Break
    }
    # Create a new folder under C:\Temp to store the old log files
    $archiveFolder = "$RootPath\$ArchiveFolderName"
    $ScratchFolder = "$ArchiveFolder\Scratch"

    # Check if the archive folder doesn't exist, and create it if necessary
    if (-not (Test-Path -Path $archiveFolder -PathType Container)) {
        New-Item -Path $archiveFolder -ItemType Directory -Force | Out-Null
    }
    #Check if Scratch Folder is there    
    if (-not (Test-Path -Path $ScratchFolder -PathType Container)) {
        New-Item -Path $ScratchFolder -ItemType Directory -Force | Out-Null
    }

    #Set the archive path
    $ArchiveName = $ArchiveFolder + "\" + $env:computername + "-" + (get-date -Format yyyyMMdd) + ".zip"

    # Get the current date
    $currentDate = Get-Date

    # Calculate the date threshold for logs to be compressed
    $dateThreshold = $currentDate.AddDays(-$daysToKeep)

    # Get a list of log files that are older than the specified threshold
    $logFiles = Get-ChildItem -Path $logDirectory -File -Recurse | Where-Object { $_.LastWriteTime -lt $dateThreshold }
    
    ##Cleanup old Archives
    $Archives = Get-ChildItem -Path $ArchiveFolder -Filter *.zip
    $ArchiveMinTimeSpan = (Get-Date).adddays(-2)
    if($Archives.count -gt $ArchivesKeepCount){
        $ArchivestoKeep = $Archives |  Sort-Object LastWriteTime -Descending | Select-object -First $ArchivesKeepCount
        $ArchivestoRemove = $Archives | Where-Object {$ArchivestoKeep.name -notcontains $_.Name}
        ##Protection for making sure to keep some .zip in-case this runs multiple times, should make sure a backup of the Zip happens before deletion
        foreach($File in $ArchivestoRemove){
            if($File.LastWriteTime -le $ArchiveMinTimeSpan){
                Remove-Item -path $File.FullName -force -verbose
            }

        }
    }

    # Move the old log files to a Scratch Folder
    $logFiles | ForEach-Object {
        Move-Item -Path $_.FullName -Destination $ScratchFolder -Force #-whatif
    }

    $ZipFiles = Get-ChildItem $ScratchFolder -File #-filter *.log

    # Check if there are any log files to compress
    if ($zipFiles.Count -gt 0) {
        # Get the PowerShell version
        $psVersion = $PSVersionTable.PSVersion

        # Check if the major version is 5 or higher
        if ($psVersion.Major -ge 5) {
            # Use Compress-Archive
            Compress-Archive -Path $ScratchFolder -DestinationPath $ArchiveName -Force
        }

        else {
            # Use .NET for archiving (for versions lower than 5)
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            # Create the ZIP archive
            [System.IO.Compression.ZipFile]::CreateFromDirectory($ScratchFolder, $ArchiveName)
        }

        # Clear the contents of the OldLogs directory
        $ScratchSize = [math]::round(($ZipFiles | Measure-Object length -sum).Sum /1gb,2)
        $ZipSize = [math]::round((get-childitem $ArchiveName | Measure-Object length -sum).Sum /1gb,2)
        $Savings = $ScratchSize - $ZipSize
        $CompressCount = $ZipFiles.count
        Remove-Item -Path $ScratchFolder\* -Force -Recurse #-verbose # -whatif
        
        Write-Host "Log files older than $daysToKeep days have been compressed."
        Write-Host "Savings of $Savings GB"
        Write-Host "Archives $CompressCount Files"
        } 

    $IISErrorPath = "C:\Windows\System32\LogFiles\HTTPERR"
    $Items = Get-ChildItem -Path $IISErrorPath |?{$_.Name -like "*.log" -and $_.LastWriteTime -lt ((Get-Date).adddays(-1))}
    $ItemCount = $Items.Count
    Write-Host "Removing:$ItemCount HTTPError Items at $IISErrorPath"
    foreach($Item in $Items){
        Remove-item $Item.FullName -force
    }


}

function Remove-OldFiles  {
<#
.SYNOPSIS
    Removes files older than a specified number of days from a given directory and its subdirectories.

.DESCRIPTION
    This function recursively searches through a specified directory and all its subdirectories, 
    removing all files older than the specified number of days and matching the specified file extensions.

.PARAMETER LogDirectory
    The root directory to start the search.

.PARAMETER Days
    The number of days to use for determining the age of files to be deleted.

.PARAMETER FileExtensions
    An array of file extensions to filter by (e.g., ".log", ".txt", ".bak").

.EXAMPLE
    Remove-OldFiles -RootDirectory "C:\Windows\System32\LogFiles" -Days 7 -FileExtensions @(".log", ".txt", ".bak")

.NOTES
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RootDirectory,

        [Parameter(Mandatory = $false)]
        [int]$Days = 14,

        [Parameter(Mandatory = $false)]
        [string[]]$FileExtensions = @(".log", ".txt", ".bak", ".zip")
    )

    process {
        try {
            $History = (Get-Date).AddDays(-$Days)

            # Get all files in the directory and subdirectories
            $Files = Get-ChildItem -Path $LogDirectory -Recurse -File | Where-Object {
                $FileExtensions -contains $_.Extension
            }

            # Filter and remove files older than $History
            foreach ($File in $Files) {
                if ($File.LastWriteTime -lt $History) {
                    Remove-Item -Path $File.FullName -Force
                }
            }

            Write-Output "Files older than $Days days with extensions $($FileExtensions -join ', ') have been removed from $LogDirectory."
        } catch {
            Write-Error "An error occurred: $_"
        }
    }
}

function Clear-AllUsersRecycleBin {
<#
.SYNOPSIS
    Cleans out the recycle bin for all users on the system.

.DESCRIPTION
    This function iterates through all user profiles on the system and empties their recycle bins.

.EXAMPLE
    Clear-AllUsersRecycleBin

.NOTES

#>

    [CmdletBinding()]
    param ()

    process {
        try {
            # Path to the Recycle Bin
            $recycleBinPath = 'C:\$Recycle.Bin'

            # Get all directories within the Recycle Bin path (each user's Recycle Bin folder)
            $userRecycleBins = Get-ChildItem -Path $recycleBinPath -Directory

            # Clean the recycle bin for each user
            foreach ($userBin in $userRecycleBins) {
                $userBinPath = $userBin.FullName
                if (Test-Path -Path $userBinPath) {
                    # Remove only files within each user's Recycle Bin folder
                    Get-ChildItem -Path $userBinPath -File | Remove-Item -Force -ErrorAction SilentlyContinue
                }
            }

            Write-Output "Recycle bins for all users have been cleaned."
        } catch {
            Write-Error "An error occurred: $_"
        }
    }
}

function Test-WinSXSCleanupNeeded {

    Try{
        $WinSXSCleanupNeeded = DISM /Online /Cleanup-Image /AnalyzeComponentStore
    } Catch {
        Write-Host "DISM Cleanup Not Supported.  Analyze Failed."
        Break
    }
    
    $WinSXSInfo = $WinSXSCleanupNeeded -replace "\s+",'' | Select-String -Pattern "ComponentStoreCleanupRecommended"
    $WinSXSSplit = $WinSXSInfo -split ":" 
    if($WinSXSSplit[1] -eq "Yes"){
        $CleanupNeeded = $true
    } else {
        $CleanupNeeded = $false
    }
    
    Return $CleanupNeeded

}

function Clear-WERFiles {
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>

##ChangeLog
# 4/4/24 - Initial Build

    $profiles = Get-ChildItem -Path "C:\Users\" -Directory -Name

    foreach ($profile in $profiles) {#}
        $werFolder = Join-Path -Path "C:\Users\$profile\AppData\Local\Microsoft\Windows\WER" -ChildPath "*"
        Remove-Item -Path $werFolder -Recurse -Force -ErrorAction SilentlyContinue

    }

    Write-Host "WER folder cleared for all user profiles."
    Get-ChildItem -Path "C:\Windows\Temp\LTCache" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } | Remove-Item -Force -Recurse
}

function Clear-TempFiles {

    $TempPaths = @()
    $TempPaths = @(
        New-Object psobject -property @{
            Name	 = "WindowsTemp"
            RootPath = $ENV:SystemRoot+'\Temp'
            Search = @("*.exe","*.msi","*.txt","*.log")
            Age = 30
            
        }
        New-Object psobject -property @{
            Name	 = "RootTemp"
            RootPath = $ENV:SystemDrive+'\Temp'
            Search = @("*.*")
            Age = 30
        }
        
    )

    foreach($TempPath in $TempPaths){ #}
        $Temp = $TempPath.RootPath
        $Files = Get-ChildItem -Path $Temp -recurse -include @($TempPath.Search) -ErrorAction SilentlyContinue
        $Age = (Get-Date).AddDays(-$TempPath.Age)
        $ActionFiles = $Files | ? {$_.LastAccessTime -lt $Age}
        $ActionSize = [math]::Round(($ActionFiles | Measure-Object -Property Length -Sum).Sum /1mb)
        foreach($File in $ActionFiles){ #}
            Remove-Item $File.FullName
        }
        $ReturnData = @{
            QTY = $ActionFiles.Count
            Location = $Temp
            SizeMB = $ActionSize

        }
        Return $ReturnData
    }

}

Export-ModuleMember -function Clear-ASPNetCache, Clear-DMPFiles, Test-WinSXSCleanupNeeded, Clear-IISLogFiles, Clear-WERFiles,
 Clear-WinSXS, Test-PendingReboot, Remove-OldFiles, Clear-AllUsersRecycleBin
