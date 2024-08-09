function Start-LocalSoftwareInstall {
##ChangeLog
    # 2/28/24 - Fixes for File picker
    
    <#
        .SYNOPSIS
        This function is used to Install Software
    
        
        .DESCRIPTION
        Suggested Output use in a script
        
    #>
    param(
        [Parameter(Mandatory=$True)]
        [String]$InstallFile,
        [Parameter(Mandatory=$False)]
        [Boolean]$Cleanup=$true,
        [Parameter(Mandatory=$False)]
        [string]$DownloadPath="C:\Temp",
        [Parameter(Mandatory=$False)]
        [Boolean]$UseCustomParam=$True,
        [Parameter(Mandatory=$False)]
        [array]$ExtraInstallStrings
    )

    if(!(Test-Path $DownloadPath)){
        New-Item -ItemType Directory -Path $DownloadPath
    }
    
    $Installer = Get-ChildItem -path $InstallFile
    
    if( ($Installer.count) -ne 1){
        Write-Host "More than One Install File Found, Aborting."
        Write-Host "Be sure to feed a single File to the install"
        Break

    }


    $InstallerName = $Installer.FullName
    $MSIDirectory = $Installer.DirectoryName
    $ShortName = $Installer.Name
    Write-Host "Verifying that: $InstallerName is not blocked"
    Unblock-File -Path $InstallerName -Confirm:$False

    Write-Host "Found File: $InstallerName"
    
    [string]$LogsEnabled = $LogsEnabled
    $LogPath = "$DownloadPath\$ShortName.log"
    
    $MSIRequired = @(
        "/i"
        """$InstallerName"""
        "/qn"
        "/norestart"
        "/l*v ""$LogPath"""
    )
    
    $MSIInstallArguments = $MSIRequired

    if($UseCustomParam -eq $true){
        $CustomParam = $null
        $CustomParam = @(Get-ChildItem -Path $MSIDirectory -filter "$ShortName.param"|get-content)
        $MSIInstallArguments = $MSIInstallArguments+ $CustomParam
    }
    
    if($ExtraInstallStrings){
        $MSIInstallArguments = $MSIInstallArguments + $ExtraInstallStrings
    }
        
    Start-Process 'msiexec.exe' -ArgumentList $MSIInstallArguments -wait -verb runas -verbose
    
    if($Cleanup -eq $true){
        Write-Host "Cleaning Up after Myself"
        Remove-Item -Path $InstallerName -Confirm:$false
        Try{Remove-Item -Path "$MSIDirectory\$ShortName.param" -Confirm:$false -ErrorAction SilentlyContinue}Catch{Out-Null}
    }

}


Function Start-RemoteSoftwareInstall{
    <#
        .SYNOPSIS
        Remotely install Software using .txt path files or a path
    
        .DESCRIPTION
        Suggested Output use in a script
        Pre-load information for Script using: 
        
        Start-RemoteSoftwareInstall  -Path "<Path to Installer>" -TargetsFQDN $TargetFQDN -Creds $Creds
        
        -Path[Required] = Path to Installers
        -TargetsFQDN[Required] = Array of FQDN servers to Target
        -Creds[Required] = Install Credentials for operation
        -Filebased[Optional] = Boolean, $false = One directory, $true, references a .txt file for each install.
        -FileFilter[Optional] = Target a specific install .txt file for getting list of software to install
        -AsJob[Optional] = $True engages a loop of software installs into a Job and monitors it until Return Data. #New 8/15/23
    
        .PARAMETER Extension
        Parameter description
    
        .PARAMETER Temporary
        Parameter description
    
        .PARAMETER TemporaryFileOnly
        Parameter description
    
        .EXAMPLE
        Get-CloudDeployment
    
        .EXAMPLE
    
        .EXAMPLE
    
        .NOTES
        General notes
        #>
    param (
            [Parameter(Mandatory = $false)]
            [string]$Filebased=$false,
            [Parameter(Mandatory = $true)]
            [string]$InstallerPath,
            [Parameter(Mandatory = $true)]
            [array]$TargetsFQDN,
            [Parameter(Mandatory = $false)]
            [SecureString] $Creds,
            [Parameter(Mandatory = $false)]
            [string]$FileFilter
            #[Parameter(Mandatory = $false)]
            #[boolean]$AsJob=$false
    )
    
        ##Pick a Filebased installer to push out multiple softwares.  Looks for a .txt file
        if($Filebased -eq $true){
            $FileCheck = get-content -path $InstallerPath -ErrorAction SilentlyContinue
            if(!$FileCheck){
                $Files = Get-ChildItem -path $InstallerPath -filter *.txt |?{$_.Name -match $FileFilter}
                $FilePaths = $Files.FullName
                
    
                if ($FilePaths.count -gt 1){
                    $IDX = 0
                    $(foreach ($File in $Files)
                        {
                            $File | Select @{ l = 'IDX'; e = { $IDX } }, Name, FullName
                            $IDX++
                    
                        }) |
                    Out-GridView -Title "Select a Target File" -OutputMode Single |
                    foreach { $ChosenFile = $FilePaths[$_.IDX] }
                }
                else {$ChosenFile = $FilePaths}
                $SourcePaths = Get-content -Path $ChosenFile
            }
           
        }else{

            $SourcePaths = $InstallerPath
        }
    
    #Verify there is some sort of file picked
        
        if(!$SourcePaths){
            Write-Host "No data in chosen file, verify there are file paths setup"
            break
        }
    
    
    ###Copy data to each target based on the input data
        ForEach ($TargetFQDN in $TargetsFQDN){
    
            $RemotePath = "\\$TargetFQDN\C$\Temp\RemoteInstalls"
            If(!(test-path $RemotePath)){
                New-Item -ItemType Directory -Force -Path $RemotePath
            }
                write-host "Copying a large amount of data, please hold....."
        
            foreach($SourcePath in $SourcePaths){
                copy-item -Path $SourcePath -Destination $RemotePath -Recurse
            }
     
        }
    
    ##Start Remote Installs
        foreach ($TargetFQDN in $TargetsFQDN){
            
            #TestCreds
            #$TestCreds = invoke-command -Authentication NegotiateWithImplicitCredential -ComputerName $TargetFQDN {get-childitem -path "C:\Temp"}
            
            
            $JobName = "Software Install: $TargetFQDN"
            
            if($AsJob -eq $false){
                invoke-command -Credential $DomainCreds -ComputerName $TargetFQDN -ScriptBlock {
                    $InstallerPath="C:\Temp\RemoteInstalls"
            
                    $Installers = Get-ChildItem -Path $InstallerPath -Recurse -Depth 1 |?{$_.Extension -match "exe" -or $_.Extension -match "msi" -or $_.Extension -match "ps1"} | Sort-Object Name
    
            
                    foreach ($Installer in $Installers){
                        $InstallerName = $Installer.FullName
                        $MSIDirectory = $Installer.DirectoryName
                        $ShortName = $Installer.Name
                        Write-Host "Verifying that: $InstallerName is not blocked"
                        Unblock-File -Path $InstallerName -Confirm:$False
    
                        Write-Host "Found File: $InstallerName"
                        $CustomParam = $null
                        $CustomParam = @(Get-ChildItem -Path $MSIDirectory -filter "InstallParam.txt"|get-content)
                
                        $MSIGenericParam = @(
                        "/i"
                        """$InstallerName"""
                        "/qn"
                        "/norestart"
                        "/l*v ""C:\Temp\$ShortName.log"""
                        )
                        $PatchPath = $Installer.DirectoryName
                        $Patch = (Get-ChildItem $PatchPath -filter *.msp).FullName
        
                        if($Patch){
                            $MSIGenericParam = $MSIGenericParam + @("/update ""$Patch""")
                        }
                
                        $EXEGenericParam = @(
                        "/q"
                        "/norestart"
                        )
                
                        if($CustomParam){
                            $MSIRequired = @(
                                "/i"
                                """$InstallerName"""
                                "/qn"
                                "/l*v ""C:\Temp\$ShortName.log"""
                                "/norestart"
                            )
                            $EXEGenericParam = $CustomParam
                            $MSIGenericParam = $MSIRequired+$CustomParam
                        }
    
                        Write-Host "Starting Install for type:"$Installer.Extension -background Green
    
                        if($Installer.Extension -eq ".msi"){
                            Write-Host "MSI Install - Param: $MSIGenericParam"
                            start-process 'msiexec.exe' -ArgumentList "$MSIGenericParam" -Verb runas -wait -Verbose
                        }
                        if($Installer.Extension -eq ".exe"){
                            Write-Host "EXE: $InstallerName Param: $EXEGenericParam"
                            start-process $InstallerName -ArgumentList "$EXEGenericParam" -verb runas -wait -Verbose
                        }
                        if($Installer.Extension -eq ".ps1"){
                            Write-Host "PS1: $InstallerName Param:"
                            Start-Process Powershell.exe -ArgumentList $InstallerName -verb runas -wait -Verbose
                        }
                    }
            
            
                    Remove-Item -path $InstallerPath -Recurse -Force
                    write-host "Cleaning up aftermyself completed"
    
                }
            }
            if($AsJob -eq $true){
                invoke-command -Credential $DomainCreds -ComputerName $TargetFQDN -ScriptBlock {
                    $InstallerPath="C:\Temp\RemoteInstalls"
            
                    $Installers = Get-ChildItem -Path $InstallerPath -Recurse -Depth 1 |?{$_.Extension -match "exe" -or $_.Extension -match "msi" -or $_.Extension -match "ps1"}
    
            
                    foreach ($Installer in $Installers){
                        $InstallerName = $Installer.FullName
                        $MSIDirectory = $Installer.DirectoryName
                        Write-Host "Verifying that: $InstallerName is not blocked"
                        Unblock-File -Path $InstallerName -Confirm:$False
    
                        Write-Host "Found File: $InstallerName"
                        $CustomParam = $null
                        $CustomParam = @(Get-ChildItem -Path $MSIDirectory -filter "InstallParam.txt"|get-content)
                
                        $MSIGenericParam = @(
                        "/i"
                        """$InstallerName"""
                        "/qn"
                        "/norestart"
                        )
                        $PatchPath = $Installer.DirectoryName
                        $Patch = (Get-ChildItem $PatchPath -filter *.msp).FullName
        
                        if($Patch){
                            $MSIGenericParam = $MSIGenericParam + @("/update ""$Patch""")
                        }
                
                        $EXEGenericParam = @(
                        "/q"
                        "/norestart"
                        )
                
                        if($CustomParam){
                            $EXEGenericParam = $CustomParam
                            $MSIGenericParam = $CustomParam
                        }
    
                        Write-Host "Starting Install for type:"$Installer.Extension -background Green
    
                        if($Installer.Extension -eq ".msi"){
                            Write-Host "MSI Install - Param: $MSIGenericParam"
                            start-process 'msiexec.exe' -ArgumentList "$MSIGenericParam" -Verb runas -wait -Verbose
                        }
                        if($Installer.Extension -eq ".exe"){
                            Write-Host "EXE: $InstallerName Param: $EXEGenericParam"
                            start-process $InstallerName -ArgumentList "$EXEGenericParam" -verb runas -wait -Verbose
                        }
                        if($Installer.Extension -eq ".ps1"){
                            Write-Host "PS1: $InstallerName Param:"
                            Start-Process Powershell.exe -ArgumentList $InstallerName -verb runas -wait -Verbose
                        }
                    }
            
            
                    Remove-Item -path $InstallerPath -Recurse -Force
                    write-host "Cleaning up aftermyself completed"
    
                } -AsJob -JobName $JobName
            }
    
        }
        
        if($AsJob -eq $true){
            $rows  = [System.Collections.ArrayList]@()
            DO{
                $Jobs = Get-Job |?{$_.name -match "Software Install"}
                $JobCount = $Jobs.count
                Write-Host "$JobCount Jobs Running" -BackgroundColor Green -ForegroundColor Black
                foreach($Job in $Jobs){ #}
                    if ($Job.State -eq "Completed" -or $Job.State -eq "Stopped"){
                        $row = [PsCustomObject]@{
                            JobName = $Job.Name
                            JobLocation = $Job.Location
                            JobStatus = $Job.Status
                            JobInfo = $Job.ChildJobs.Output
                        }
                        [void]$rows.Add($row)
                        Remove-Job $Job
                    }
                    if ($Job.State -eq "Failed" -or $Job.ChildJobs.Output -eq "Failed"){
                        Write-Host $Job.name "Failed on host" $Job.Name
                        $row = [PsCustomObject]@{
                            JobName = $Job.Name
                            JobLocation = $Job.Location
                            JobStatus = $Job.Status
                            JobInfo = $Job.ChildJobs.Output
                        }
                        [void]$rows.Add($row)
                        Remove-Job $Job
                    }
                    #if ($Job.State -ne "Completed" -or $Job.State -ne "Running"){Write-Host "Issue with $Job"}
    
                    $ActiveJob = $job
                    Write-Host "Job:"$ActiveJob.ChildJobs.Output"| Status:"$ActiveJob.State
                    
                }
            Start-Sleep -seconds 120
    
            }until($Jobs.count  -eq 0)
    
            Return $rows
        }
    
          
    }
    

Export-ModuleMember -function Start-LocalSoftwareInstall, Start-RemoteSoftwareInstall