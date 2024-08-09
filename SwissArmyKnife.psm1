
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
        [Parameter(Mandatory = $True)]
        [String]$InstallFile,
        [Parameter(Mandatory = $False)]
        [Boolean]$Cleanup = $true,
        [Parameter(Mandatory = $False)]
        [string]$DownloadPath = "C:\Temp",
        [Parameter(Mandatory = $False)]
        [Boolean]$UseCustomParam = $True,
        [Parameter(Mandatory = $False)]
        [array]$ExtraInstallStrings
    )
    
    if (!(Test-Path $DownloadPath)) {
        New-Item -ItemType Directory -Path $DownloadPath
    }
        
    $Installer = Get-ChildItem -path $InstallFile
        
    if ( ($Installer.count) -ne 1) {
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
    
    if ($UseCustomParam -eq $true) {
        $CustomParam = $null
        $CustomParam = @(Get-ChildItem -Path $MSIDirectory -filter "$ShortName.param" | get-content)
        $MSIInstallArguments = $MSIInstallArguments + $CustomParam
    }
        
    if ($ExtraInstallStrings) {
        $MSIInstallArguments = $MSIInstallArguments + $ExtraInstallStrings
    }
            
    Start-Process 'msiexec.exe' -ArgumentList $MSIInstallArguments -wait -verb runas -verbose
        
    if ($Cleanup -eq $true) {
        Write-Host "Cleaning Up after Myself"
        Remove-Item -Path $InstallerName -Confirm:$false
        Try { Remove-Item -Path "$MSIDirectory\$ShortName.param" -Confirm:$false -ErrorAction SilentlyContinue }Catch { Out-Null }
    }
    
}
    
    
Function Start-RemoteSoftwareInstall {
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
        [string]$Filebased = $false,
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
    if ($Filebased -eq $true) {
        $FileCheck = get-content -path $InstallerPath -ErrorAction SilentlyContinue
        if (!$FileCheck) {
            $Files = Get-ChildItem -path $InstallerPath -filter *.txt | ? { $_.Name -match $FileFilter }
            $FilePaths = $Files.FullName
                    
        
            if ($FilePaths.count -gt 1) {
                $IDX = 0
                $(foreach ($File in $Files) {
                        $File | Select @{ l = 'IDX'; e = { $IDX } }, Name, FullName
                        $IDX++
                        
                    }) |
                Out-GridView -Title "Select a Target File" -OutputMode Single |
                foreach { $ChosenFile = $FilePaths[$_.IDX] }
            }
            else { $ChosenFile = $FilePaths }
            $SourcePaths = Get-content -Path $ChosenFile
        }
               
    }
    else {
    
        $SourcePaths = $InstallerPath
    }
        
    #Verify there is some sort of file picked
            
    if (!$SourcePaths) {
        Write-Host "No data in chosen file, verify there are file paths setup"
        break
    }
        
        
    ###Copy data to each target based on the input data
    ForEach ($TargetFQDN in $TargetsFQDN) {
        
        $RemotePath = "\\$TargetFQDN\C$\Temp\RemoteInstalls"
        If (!(test-path $RemotePath)) {
            New-Item -ItemType Directory -Force -Path $RemotePath
        }
        write-host "Copying a large amount of data, please hold....."
            
        foreach ($SourcePath in $SourcePaths) {
            copy-item -Path $SourcePath -Destination $RemotePath -Recurse
        }
         
    }
        
    ##Start Remote Installs
    foreach ($TargetFQDN in $TargetsFQDN) {
                
        #TestCreds
        #$TestCreds = invoke-command -Authentication NegotiateWithImplicitCredential -ComputerName $TargetFQDN {get-childitem -path "C:\Temp"}
                
                
        $JobName = "Software Install: $TargetFQDN"
                
        if ($AsJob -eq $false) {
            invoke-command -Credential $DomainCreds -ComputerName $TargetFQDN -ScriptBlock {
                $InstallerPath = "C:\Temp\RemoteInstalls"
                
                $Installers = Get-ChildItem -Path $InstallerPath -Recurse -Depth 1 | ? { $_.Extension -match "exe" -or $_.Extension -match "msi" -or $_.Extension -match "ps1" } | Sort-Object Name
        
                
                foreach ($Installer in $Installers) {
                    $InstallerName = $Installer.FullName
                    $MSIDirectory = $Installer.DirectoryName
                    $ShortName = $Installer.Name
                    Write-Host "Verifying that: $InstallerName is not blocked"
                    Unblock-File -Path $InstallerName -Confirm:$False
        
                    Write-Host "Found File: $InstallerName"
                    $CustomParam = $null
                    $CustomParam = @(Get-ChildItem -Path $MSIDirectory -filter "InstallParam.txt" | get-content)
                    
                    $MSIGenericParam = @(
                        "/i"
                        """$InstallerName"""
                        "/qn"
                        "/norestart"
                        "/l*v ""C:\Temp\$ShortName.log"""
                    )
                    $PatchPath = $Installer.DirectoryName
                    $Patch = (Get-ChildItem $PatchPath -filter *.msp).FullName
            
                    if ($Patch) {
                        $MSIGenericParam = $MSIGenericParam + @("/update ""$Patch""")
                    }
                    
                    $EXEGenericParam = @(
                        "/q"
                        "/norestart"
                    )
                    
                    if ($CustomParam) {
                        $MSIRequired = @(
                            "/i"
                            """$InstallerName"""
                            "/qn"
                            "/l*v ""C:\Temp\$ShortName.log"""
                            "/norestart"
                        )
                        $EXEGenericParam = $CustomParam
                        $MSIGenericParam = $MSIRequired + $CustomParam
                    }
        
                    Write-Host "Starting Install for type:"$Installer.Extension -background Green
        
                    if ($Installer.Extension -eq ".msi") {
                        Write-Host "MSI Install - Param: $MSIGenericParam"
                        start-process 'msiexec.exe' -ArgumentList "$MSIGenericParam" -Verb runas -wait -Verbose
                    }
                    if ($Installer.Extension -eq ".exe") {
                        Write-Host "EXE: $InstallerName Param: $EXEGenericParam"
                        start-process $InstallerName -ArgumentList "$EXEGenericParam" -verb runas -wait -Verbose
                    }
                    if ($Installer.Extension -eq ".ps1") {
                        Write-Host "PS1: $InstallerName Param:"
                        Start-Process Powershell.exe -ArgumentList $InstallerName -verb runas -wait -Verbose
                    }
                }
                
                
                Remove-Item -path $InstallerPath -Recurse -Force
                write-host "Cleaning up aftermyself completed"
        
            }
        }
        if ($AsJob -eq $true) {
            invoke-command -Credential $DomainCreds -ComputerName $TargetFQDN -ScriptBlock {
                $InstallerPath = "C:\Temp\RemoteInstalls"
                
                $Installers = Get-ChildItem -Path $InstallerPath -Recurse -Depth 1 | ? { $_.Extension -match "exe" -or $_.Extension -match "msi" -or $_.Extension -match "ps1" }
        
                
                foreach ($Installer in $Installers) {
                    $InstallerName = $Installer.FullName
                    $MSIDirectory = $Installer.DirectoryName
                    Write-Host "Verifying that: $InstallerName is not blocked"
                    Unblock-File -Path $InstallerName -Confirm:$False
        
                    Write-Host "Found File: $InstallerName"
                    $CustomParam = $null
                    $CustomParam = @(Get-ChildItem -Path $MSIDirectory -filter "InstallParam.txt" | get-content)
                    
                    $MSIGenericParam = @(
                        "/i"
                        """$InstallerName"""
                        "/qn"
                        "/norestart"
                    )
                    $PatchPath = $Installer.DirectoryName
                    $Patch = (Get-ChildItem $PatchPath -filter *.msp).FullName
            
                    if ($Patch) {
                        $MSIGenericParam = $MSIGenericParam + @("/update ""$Patch""")
                    }
                    
                    $EXEGenericParam = @(
                        "/q"
                        "/norestart"
                    )
                    
                    if ($CustomParam) {
                        $EXEGenericParam = $CustomParam
                        $MSIGenericParam = $CustomParam
                    }
        
                    Write-Host "Starting Install for type:"$Installer.Extension -background Green
        
                    if ($Installer.Extension -eq ".msi") {
                        Write-Host "MSI Install - Param: $MSIGenericParam"
                        start-process 'msiexec.exe' -ArgumentList "$MSIGenericParam" -Verb runas -wait -Verbose
                    }
                    if ($Installer.Extension -eq ".exe") {
                        Write-Host "EXE: $InstallerName Param: $EXEGenericParam"
                        start-process $InstallerName -ArgumentList "$EXEGenericParam" -verb runas -wait -Verbose
                    }
                    if ($Installer.Extension -eq ".ps1") {
                        Write-Host "PS1: $InstallerName Param:"
                        Start-Process Powershell.exe -ArgumentList $InstallerName -verb runas -wait -Verbose
                    }
                }
                
                
                Remove-Item -path $InstallerPath -Recurse -Force
                write-host "Cleaning up aftermyself completed"
        
            } -AsJob -JobName $JobName
        }
        
    }
            
    if ($AsJob -eq $true) {
        $rows = [System.Collections.ArrayList]@()
        DO {
            $Jobs = Get-Job | ? { $_.name -match "Software Install" }
            $JobCount = $Jobs.count
            Write-Host "$JobCount Jobs Running" -BackgroundColor Green -ForegroundColor Black
            foreach ($Job in $Jobs) {
                #}
                if ($Job.State -eq "Completed" -or $Job.State -eq "Stopped") {
                    $row = [PsCustomObject]@{
                        JobName     = $Job.Name
                        JobLocation = $Job.Location
                        JobStatus   = $Job.Status
                        JobInfo     = $Job.ChildJobs.Output
                    }
                    [void]$rows.Add($row)
                    Remove-Job $Job
                }
                if ($Job.State -eq "Failed" -or $Job.ChildJobs.Output -eq "Failed") {
                    Write-Host $Job.name "Failed on host" $Job.Name
                    $row = [PsCustomObject]@{
                        JobName     = $Job.Name
                        JobLocation = $Job.Location
                        JobStatus   = $Job.Status
                        JobInfo     = $Job.ChildJobs.Output
                    }
                    [void]$rows.Add($row)
                    Remove-Job $Job
                }
                #if ($Job.State -ne "Completed" -or $Job.State -ne "Running"){Write-Host "Issue with $Job"}
        
                $ActiveJob = $job
                Write-Host "Job:"$ActiveJob.ChildJobs.Output"| Status:"$ActiveJob.State
                        
            }
            Start-Sleep -seconds 120
        
        }until($Jobs.count -eq 0)
        
        Return $rows
    }
        
              
}
        
Function Grant-ADPermission {
    <#
    .SYNOPSIS
        Add Access Control Entry on Active Directory Organizational Unit.
    .DESCRIPTION
        This function will create ACE and add them to the specified AD OU's.
    .EXAMPLE
        Grant-ADPermission -GroupDistinguishedName 'CN=Applications2,OU=Groups,DC=D2K12R2,DC=local' -AdRights WriteProperty -AccessControlType Allow -Inheritance Children -ObjectType user -InheritedObjectType user -OrgUnitDN 'OU=Test,DC=D2K12R2,DC=local'
    .EXAMPLE
        Grant-ADPermission -GroupDistinguishedName 'CN=StarWars-Computers_CreateDelete,OU=Groups,OU=Admins,DC=D2K8R2,DC=itfordummies,DC=net' -AdRights CreateChild,DeleteChild -AccessControlType Allow -Inheritance Children -OrgUnitDN 'OU=Computers,OU=Star Wars,OU=Production,DC=D2K8R2,DC=itfordummies,DC=net' -ObjectType computer -InheritedObjectType null -Verbose
    .EXAMPLE
        'OU=lvl2,OU=Test,DC=D2K12R2,DC=local','OU=Trash,OU=Test,DC=D2K12R2,DC=local' | Grant-ADPermission -GroupDistinguishedName 'CN=Applications2,OU=Groups,DC=D2K12R2,DC=local' -AdRights WriteProperty -AccessControlType Allow -Inheritance Children -ObjectType user -InheritedObjectType user
    .PARAMETER GroupDistinguishedName
        DistinguishedName of the group to give permission to.
    .PARAMETER AdRights
        System.DirectoryServices.ActiveDirectoryRights, autocompletion should work from PS3+.
    .PARAMETER AccessControlType
        System.Security.AccessControl.AccessControlType, autocompletion should work from PS3+.
    .PARAMETER Inheritance
        System.DirectoryServices.ActiveDirectorySecurityInheritance, autocompletion should work from PS3+.
    .PARAMETER OrgUnitDN
        String[] containing the list of OU to delegate. You can specify more than one, and use pipeline input.
    .PARAMETER InheritedObjectType
        Dynamic param containing LDAPName of all schema objects. The function will use the associated GUID.
    .PARAMETER ObjectType
        Dynamic param containing LDAPName of all schema objects. The function will use the associated GUID.
    .INPUTS
    .OUTPUTS
    .NOTES
        Uses Dynamic Parameters.
    .LINK
        http://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]$GroupDistinguishedName,

        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectoryRights[]]$AdRights,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,

        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Inheritance,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [String[]]$OrgUnitDN,

        [Switch]$PassThru
    )

    DynamicParam {
        #region ObjectType
        # Set the dynamic parameters' name
        $ParameterName = 'ObjectType'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 1

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet
        $DomainName = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        $MasterGuidMap = @{}
        $SchemaGuidMapSearcher = [ADSISearcher]'(schemaidguid=*)'
        $SchemaGuidMapSearcher.SearchRoot = [ADSI]"LDAP://CN=Schema,$(([ADSI]"LDAP://$DomainName/RootDSE").configurationNamingContext)"
        $null = $SchemaGuidMapSearcher.PropertiesToLoad.AddRange(('ldapdisplayname', 'schemaidguid'))
        $SchemaGuidMapSearcher.PageSize = 10000
        $SchemaGuidMapSearcher.FindAll() | Foreach-Object -Process {
            #$MasterGuidMap[(New-Object -TypeName Guid -ArgumentList (,$_.properties.schemaidguid[0])).Guid] = "$($_.properties.ldapdisplayname)"
            $MasterGuidMap["$($_.properties.ldapdisplayname)"] = (New-Object -TypeName Guid -ArgumentList (, $_.properties.schemaidguid[0])).Guid
        } -End { $MasterGuidMap['null'] = [Guid]'00000000-0000-0000-0000-000000000000' }
        $DynamicParamValue = $MasterGuidMap.Keys

        #$DynamicParamValue
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($DynamicParamValue)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter) #ForEach DynamicParam
        #endregion

        #region InheritedObjectType
        #Second DynParam
        # Set the dynamic parameters' name
        $ParameterName = 'InheritedObjectType'
            
        # Create the dictionary 
        #$RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary #Already created

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 1

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet
        #$DomainName = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        #$MasterGuidMap = @{}
        $RightsGuidMapSearcher = [ADSISearcher]'(&(objectclass=controlAccessRight)(rightsguid=*))'
        $RightsGuidMapSearcher.SearchRoot = [ADSI]"LDAP://CN=Schema,$(([ADSI]"LDAP://$DomainName/RootDSE").configurationNamingContext)"
        $null = $RightsGuidMapSearcher.PropertiesToLoad.AddRange(('displayname', 'rightsGuid'))
        $RightsGuidMapSearcher.PageSize = 10000
        $RightsGuidMapSearcher.FindAll() | Foreach-Object -Process {
            #$MasterGuidMap[(New-Object -TypeName Guid -ArgumentList (,$_.properties.rightsguid[0])).Guid] = "$($_.properties.displayname)"
            $MasterGuidMap["$($_.properties.displayname)"] = (New-Object -TypeName Guid -ArgumentList (, $_.properties.rightsguid[0])).Guid
        } -End { $MasterGuidMap['null'] = [Guid]'00000000-0000-0000-0000-000000000000' }
        $DynamicParamValue = $MasterGuidMap.Keys

        #$DynamicParamValue
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($DynamicParamValue)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter) #ForEach DynamicParam
        #endregion

        #Output
        $RuntimeParameterDictionary
    }

    Begin {
        #Dynamic Param
        $PsBoundParameters.GetEnumerator() | ForEach-Object -Process { New-Variable -Name $_.Key -Value $_.Value -ErrorAction 'SilentlyContinue' }

        #Prepare the Access Control Entry, force the type for constructor binding
        Write-Verbose -Message 'Preparing Access Control Entry attributes...'
        [System.Security.Principal.SecurityIdentifier]$Identity = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $(([ADSI]"LDAP://$GroupDistinguishedName").ObjectSid), 0).value #Get nice SID format
        [Guid]$InheritedObjectTypeValue = $MasterGuidMap[$InheritedObjectType]
        [Guid]$ObjectTypeValue = $MasterGuidMap[$ObjectType]

        #Create the Access Control Entry
        Write-Verbose -Message 'Creating Access Control Entry...'
        $NewAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $AdRights, $AccessControlType, $ObjectTypeValue, $Inheritance, $InheritedObjectTypeValue
    }
    Process {
        try {
            Write-Verbose -Message "Connecting to $OrgUnitDN"
            $ADObject = [ADSI]("LDAP://" + $OrgUnitDN)
            $ADObject.ObjectSecurity.AddAccessRule($NewAce)
            Write-Verbose -Message 'Applying Access Control Entry'
            $ADObject.CommitChanges()
            if ($PassThru) {
                $ADObject.ObjectSecurity.Access
            }
        }
        catch {
            throw "$OrgUnitDN $_"
        }
    }
    End {}
}

function Convert-IpAddressToMaskLength([string]$dottedIpAddressString) {
    $result = 0;
    # ensure we have a valid IP address
    [IPAddress]$ip = $dottedIpAddressString;
    $octets = $ip.IPAddressToString.Split('.');
    foreach ($octet in $octets) {
        while (0 -ne $octet) {
            $octet = ($octet -shl 1) -band [byte]::MaxValue
            $result++;
        }
    }
    return $result;
}


function Test-IPAddress([string]$dottedIpAddressString) {
    <#
        .SYNOPSIS
        Test if an IP input is valid structure and return $true or $false.
        
        .DESCRIPTION
        Suggested Output use in a script
    
        Do{$IPInput=Read-Host "Enter IP (Ex. 1.1.1.1)"} While ((Test-IPAddress $IPInput) -eq $false)
    
    #>
    
    $IPv4Pattern = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$"
    if ($dottedIpAddressString -match $IPv4Pattern) {
        return $true
    }
    else {
        return $false
    }
}
    
function Convert-Subnetmask {
    <#
        .SYNOPSIS
        Convert a subnetmask to CIDR and vise versa
        .DESCRIPTION
        Convert a subnetmask like 255.255.255 to CIDR (/24) and vise versa.
                    
        .EXAMPLE
        Convert-Subnetmask -CIDR 24
        Mask          CIDR
        ----          ----
        255.255.255.0   24
        .EXAMPLE
        Convert-Subnetmask -Mask 255.255.0.0
        Mask        CIDR
        ----        ----
        255.255.0.0   16
        
        .LINK
        https://github.com/BornToBeRoot/PowerShell/blob/master/Documentation/Function/Convert-Subnetmask.README.md
       
    #>
    [CmdLetBinding(DefaultParameterSetName = 'CIDR')]
    param( 
        [Parameter( 
            ParameterSetName = 'CIDR',       
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'CIDR like /24 without "/"')]
        [ValidateRange(0, 32)]
        [Int32]$CIDR,
    
        [Parameter(
            ParameterSetName = 'Mask',
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Subnetmask like 255.255.255.0')]
        [ValidateScript({
                if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$") {
                    return $true
                }
                else {
                    throw "Enter a valid subnetmask (like 255.255.255.0)!"    
                }
            })]
        [String]$Mask
    )
    
    Begin {
    
    }
    
    Process {
        switch ($PSCmdlet.ParameterSetName) {
            "CIDR" {                          
                # Make a string of bits (24 to 11111111111111111111111100000000)
                $CIDR_Bits = ('1' * $CIDR).PadRight(32, "0")
                    
                # Split into groups of 8 bits, convert to Ints, join up into a string
                $Octets = $CIDR_Bits -split '(.{8})' -ne ''
                $Mask = ($Octets | ForEach-Object -Process { [Convert]::ToInt32($_, 2) }) -join '.'
            }
    
            "Mask" {
                # Convert the numbers into 8 bit blocks, join them all together, count the 1
                $Octets = $Mask.ToString().Split(".") | ForEach-Object -Process { [Convert]::ToString($_, 2) }
                $CIDR_Bits = ($Octets -join "").TrimEnd("0")
    
                # Count the "1" (111111111111111111111111 --> /24)                     
                $CIDR = $CIDR_Bits.Length             
            }               
        }
    
        [pscustomobject] @{
            Mask = $Mask
            CIDR = $CIDR
        }
    }
    
    End {
            
    }
}
    
Function Confirm-RunAsAdministrator() {
    #Get current user context
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    
    #Check user is running the script is member of Administrator Group
    if ($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-host "Script is running with Administrator privileges!"
    }
    else {
        #Create a new Elevated process to Start PowerShell
        $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
    
        # Specify the current script path and name as a parameter
        $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
    
        #Set the Process to elevated
        $ElevatedProcess.Verb = "runas"
    
        #Start the new elevated process
        [System.Diagnostics.Process]::Start($ElevatedProcess)
    
        #Exit from the current, unelevated, process
        Exit
    
    }
}


function Find-Folders {
    param(
        $FolderPath = "c:\temp"

    )
    [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $browse = New-Object System.Windows.Forms.FolderBrowserDialog
    $browse.SelectedPath = $FolderPath
    $browse.ShowNewFolderButton = $false
    $browse.Description = "Select a directory"

   

    $loop = $true
    while ($loop) {
        if ($browse.ShowDialog() -eq "OK") {
            $loop = $false
		
            #Insert your script here
		
        }
        else {
            $res = [System.Windows.Forms.MessageBox]::Show("You clicked Cancel. Would you like to try again or exit?", "Select a location", [System.Windows.Forms.MessageBoxButtons]::RetryCancel)
            if ($res -eq "Cancel") {
                #Ends script
                return
            }
        }
    }
    $browse.SelectedPath
    $browse.Dispose()
}

Function Get-DiskFree {
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('hostname')]
        [Alias('cn')]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Position = 1,
            Mandatory = $false)]
        [Alias('runas')]
        [System.Management.Automation.Credential()]
        $Credential =
        [System.Management.Automation.PSCredential]::Empty,
        [Parameter(Position = 2)]
        [switch]$Format
    )
	
    BEGIN {
        function Format-HumanReadable {
            param ($size)
            switch ($size) {
                { $_ -ge 1PB } { "{0:#.#'P'}" -f ($size / 1PB); break }
                { $_ -ge 1TB } { "{0:#.#'T'}" -f ($size / 1TB); break }
                { $_ -ge 1GB } { "{0:#.#'G'}" -f ($size / 1GB); break }
                { $_ -ge 1MB } { "{0:#.#'M'}" -f ($size / 1MB); break }
                { $_ -ge 1KB } { "{0:#'K'}" -f ($size / 1KB); break }
                default { "{0}" -f ($size) + "B" }
            }
        }
		
        $wmiq = 'SELECT * FROM Win32_LogicalDisk WHERE Size != Null AND DriveType >= 2'
    }
	
    PROCESS {
        foreach ($computer in $ComputerName) {
            try {
                if ($computer -eq $env:COMPUTERNAME) {
                    $disks = Get-WmiObject -Query $wmiq `
                        -ComputerName $computer -ErrorAction Stop
                }
                else {
                    $disks = Get-WmiObject -Query $wmiq `
                        -ComputerName $computer -Credential $Credential `
                        -ErrorAction Stop
                }
				
                if ($Format) {
                    # Create array for $disk objects and then populate
                    $diskarray = @()
                    $disks | ForEach-Object { $diskarray += $_ }
					
                    $diskarray | Select-Object @{ n = 'Name'; e = { $computer } },
                    @{ n = 'Vol'; e = { $_.DeviceID } },
                    @{ n = 'Size'; e = { Format-HumanReadable $_.Size } },
                    @{ n = 'Used'; e = { Format-HumanReadable (($_.Size) - ($_.FreeSpace)) } },
                    @{ n = 'Avail'; e = { Format-HumanReadable $_.FreeSpace } },
                    @{ n = 'Use%'; e = { [int](((($_.Size) - ($_.FreeSpace)) / ($_.Size) * 100)) } },
                    @{ n = 'FS'; e = { $_.FileSystem } },
                    @{ n = 'Type'; e = { $_.Description } }
                }
                else {
                    foreach ($disk in $disks) {
                        $diskprops = @{
                            'Volume'     = $disk.DeviceID;
                            'Size'       = $disk.Size;
                            'Used'       = ($disk.Size - $disk.FreeSpace);
                            'Available'  = $disk.FreeSpace;
                            'FileSystem' = $disk.FileSystem;
                            'Type'       = $disk.Description
                            'Computer'   = $disk.SystemName;
                        }
						
                        # Create custom PS object and apply type
                        $diskobj = New-Object -TypeName PSObject `
                            -Property $diskprops
                        $diskobj.PSObject.TypeNames.Insert(0, 'BinaryNature.DiskFree')
						
                        Write-Output $diskobj
                    }
                }
            }
            catch {
                # Check for common DCOM errors and display "friendly" output
                switch ($_) {
                    { $_.Exception.ErrorCode -eq 0x800706ba } `
                    {
                        $err = 'Unavailable (Host Offline or Firewall)';
                        break;
                    }
                    { $_.CategoryInfo.Reason -eq 'UnauthorizedAccessException' } `
                    {
                        $err = 'Access denied (Check User Permissions)';
                        break;
                    }
                    default { $err = $_.Exception.Message }
                }
                Write-Warning "$computer - $err"
            }
        }
    }
	
    END { }
}

Function Get-FileName($InitialDirectory, $Title) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $InitialDirectory
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.Title = $Title
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.FileName
}

Function Get-ZipFile($InitialDirectory, $Title) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.filter = "Zip files (*.zip)| *.zip"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.Title = $Title
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.FileName
}

Function Get-CSVFile($InitialDirectory, $Title) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.filter = "CSV files (*.csv)| *.csv"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.Title = $Title
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.FileName
}

Function Get-SQLFile($InitialDirectory, $Title) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.filter = "SQL files (*.sql)| *.sql"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.Title = $Title
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.FileName
}

Function Get-FolderPath($InitialDirectory, $Title) {


    $sourcecode = @"
using System;
using System.Windows.Forms;
using System.Reflection;
namespace FolderSelect
{
	public class FolderSelectDialog
	{
		System.Windows.Forms.OpenFileDialog ofd = null;
		public FolderSelectDialog()
		{
			ofd = new System.Windows.Forms.OpenFileDialog();
			ofd.Filter = "Folders|\n";
			ofd.AddExtension = false;
			ofd.CheckFileExists = false;
			ofd.DereferenceLinks = true;
			ofd.Multiselect = false;
		}
		public string InitialDirectory
		{
			get { return ofd.InitialDirectory; }
			set { ofd.InitialDirectory = value == null || value.Length == 0 ? Environment.CurrentDirectory : value; }
		}
		public string Title
		{
			get { return ofd.Title; }
			set { ofd.Title = value == null ? "Select a folder" : value; }
		}
		public string FileName
		{
			get { return ofd.FileName; }
		}
		public bool ShowDialog()
		{
			return ShowDialog(IntPtr.Zero);
		}
		public bool ShowDialog(IntPtr hWndOwner)
		{
			bool flag = false;

			if (Environment.OSVersion.Version.Major >= 6)
			{
				var r = new Reflector("System.Windows.Forms");
				uint num = 0;
				Type typeIFileDialog = r.GetType("FileDialogNative.IFileDialog");
				object dialog = r.Call(ofd, "CreateVistaDialog");
				r.Call(ofd, "OnBeforeVistaDialog", dialog);
				uint options = (uint)r.CallAs(typeof(System.Windows.Forms.FileDialog), ofd, "GetOptions");
				options |= (uint)r.GetEnum("FileDialogNative.FOS", "FOS_PICKFOLDERS");
				r.CallAs(typeIFileDialog, dialog, "SetOptions", options);
				object pfde = r.New("FileDialog.VistaDialogEvents", ofd);
				object[] parameters = new object[] { pfde, num };
				r.CallAs2(typeIFileDialog, dialog, "Advise", parameters);
				num = (uint)parameters[1];
				try
				{
					int num2 = (int)r.CallAs(typeIFileDialog, dialog, "Show", hWndOwner);
					flag = 0 == num2;
				}
				finally
				{
					r.CallAs(typeIFileDialog, dialog, "Unadvise", num);
					GC.KeepAlive(pfde);
				}
			}
			else
			{
				var fbd = new FolderBrowserDialog();
				fbd.Description = this.Title;
				fbd.SelectedPath = this.InitialDirectory;
				fbd.ShowNewFolderButton = false;
				if (fbd.ShowDialog(new WindowWrapper(hWndOwner)) != DialogResult.OK) return false;
				ofd.FileName = fbd.SelectedPath;
				flag = true;
			}
			return flag;
		}
	}
	public class WindowWrapper : System.Windows.Forms.IWin32Window
	{
		public WindowWrapper(IntPtr handle)
		{
			_hwnd = handle;
		}
		public IntPtr Handle
		{
			get { return _hwnd; }
		}

		private IntPtr _hwnd;
	}
	public class Reflector
	{
		string m_ns;
		Assembly m_asmb;
		public Reflector(string ns)
			: this(ns, ns)
		{ }
		public Reflector(string an, string ns)
		{
			m_ns = ns;
			m_asmb = null;
			foreach (AssemblyName aN in Assembly.GetExecutingAssembly().GetReferencedAssemblies())
			{
				if (aN.FullName.StartsWith(an))
				{
					m_asmb = Assembly.Load(aN);
					break;
				}
			}
		}
		public Type GetType(string typeName)
		{
			Type type = null;
			string[] names = typeName.Split('.');

			if (names.Length > 0)
				type = m_asmb.GetType(m_ns + "." + names[0]);

			for (int i = 1; i < names.Length; ++i) {
				type = type.GetNestedType(names[i], BindingFlags.NonPublic);
			}
			return type;
		}
		public object New(string name, params object[] parameters)
		{
			Type type = GetType(name);
			ConstructorInfo[] ctorInfos = type.GetConstructors();
			foreach (ConstructorInfo ci in ctorInfos) {
				try {
					return ci.Invoke(parameters);
				} catch { }
			}

			return null;
		}
		public object Call(object obj, string func, params object[] parameters)
		{
			return Call2(obj, func, parameters);
		}
		public object Call2(object obj, string func, object[] parameters)
		{
			return CallAs2(obj.GetType(), obj, func, parameters);
		}
		public object CallAs(Type type, object obj, string func, params object[] parameters)
		{
			return CallAs2(type, obj, func, parameters);
		}
		public object CallAs2(Type type, object obj, string func, object[] parameters) {
			MethodInfo methInfo = type.GetMethod(func, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			return methInfo.Invoke(obj, parameters);
		}
		public object Get(object obj, string prop)
		{
			return GetAs(obj.GetType(), obj, prop);
		}
		public object GetAs(Type type, object obj, string prop) {
			PropertyInfo propInfo = type.GetProperty(prop, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			return propInfo.GetValue(obj, null);
		}
		public object GetEnum(string typeName, string name) {
			Type type = GetType(typeName);
			FieldInfo fieldInfo = type.GetField(name);
			return fieldInfo.GetValue(null);
		}
	}
}
"@
    $assemblies = ('System.Windows.Forms', 'System.Reflection')
    Add-Type -TypeDefinition $sourceCode -ReferencedAssemblies $assemblies -ErrorAction STOP
    if (!$Title) { $Title = "Select Folder" }
    $fsd = New-Object FolderSelect.FolderSelectDialog
    $fsd.InitialDirectory = $InitialDirectory
    $fsd.Title = $Title;
    $fsd.ShowDialog() | Out-Null
    $fsd.FileName
}

function Test-PFXImportFile {
    <#
        .SYNOPSIS
        Prepare a PFX Import and Test the Password and return the Cert Information for other use
    
        .DESCRIPTION
        Suggested Output use in a script
        
        Example use
        Test-PFXImportFile
            
        .PARAMETER Extension
        Parameter description
    
        .PARAMETER Temporary
        Parameter description
    
        .PARAMETER TemporaryFileOnly
        Parameter description
    
        .EXAMPLE
        Test-PFXImportFile
    
        .EXAMPLE
    
        .EXAMPLE
    
        .NOTES
        General notes
        #>	
    param (
        [Parameter(Mandatory = $False)]
        [string]$FilePath,
        [Parameter(Mandatory = $False)]
        [String]$Password,
        [Parameter(Mandatory = $False)]
        [array]$TestPass = $true
    
    )
    
        
    ###Get the Cert File
        
    #Validate and Inbound FilePath
    if ($FilePath) {
        Try {
            $TestPath = Test-Path $FilePath
            if ($TestPath = $true -and $FilePath -like "*.pfx") {
                $FileValid = $True
            }
            Else {
                $FileValid = $False
            }
        }
        Catch { $FileValid = $False }
    }
    else {
        $FileValid = $False
    }
    
    if ($FileValid -ne $true) {
                    
        $ImportFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
            InitialDirectory = $null 
            Filter           = 'SelectPFX on UNC (*.PFX)|*.PFX'
        }
        $null = $ImportFile.ShowDialog()
        $CertPath = $ImportFile.FileName
    }
    else {
        $CertPath = $FilePath
    }
    
    
    if (!$CertPath) {
        Write-Host "Certificate Missing, Stopping" -BackgroundColor Red -ForegroundColor Black
        break
    }
    
    
    Do {
        $CertPass = Read-Host -Prompt "Enter the password for the PFX file" -AsSecureString
    
        # Convert the secure string password to a plain text string
        $passwordPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertPass))
    
        # Try to load the certificate using the provided password
        try {
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath, $passwordPlainText, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            $CertTest = $true 
            Write-Host "Password test successful. The provided password is correct."
        }
        catch {
            Write-Host "Password test failed. The provided password is incorrect or the file is not a valid .PFX file." -ForegroundColor Red
            $CertTest = $false
        }
    } Until ($CertTest -eq $true)
    
    $ReturnData = @{}
    $ReturnData = [ordered]@{
        Success  = $CertTest
        CertPath = $CertPath
        CertPass = $CertPass
    }
    Return $ReturnData
}
    
function Copy-File {
    param (
        [Parameter(Mandatory = $True)]
        [string]$Source,
        [Parameter(Mandatory = $True)]
        [String]$Destination
    
    )
    
    $shell = New-Object -ComObject "Shell.Application"
    $shell.NameSpace($Destination).CopyHere($Source)
}
    
function Start-LoggingRetention {
    <#
        .SYNOPSIS
        Create Transcript logging for powershell output
    
        .DESCRIPTION
        Suggested Output use in a script
        
        Example use
        Start-LoggingRetention  -LogPath "<C:\Temp>" -LogFolder "Logging" -LogName "DiskCleanup"
            
        .PARAMETER Extension
        Parameter description
    
        .PARAMETER Temporary
        Parameter description
    
        .PARAMETER TemporaryFileOnly
        Parameter description
    
        .EXAMPLE
        ###
    
        .EXAMPLE
    
        .EXAMPLE
    
        .NOTES
        General notes
        #>	
    
    param (
        [Parameter(Mandatory = $True)]
        [string]$LogPath,
        [Parameter(Mandatory = $True)]
        [string]$LogFolder,
        [Parameter(Mandatory = $True)]
        [String]$LogName,
        [Parameter(Mandatory = $False)]
        [String]$LoggingRetentionDays = 90,
        [Parameter(Mandatory = $False)]
        [String]$LoggingRetentionMB = 20
    
    )  
        
    #region Begin Logging
    try { stop-transcript | out-null }
    catch { }
    
    
    $LogPath = "$LogPath\$LogFolder\$LogName`_$env:USERNAME.log"
    $ParentLogFolder = Split-Path -Path $LogPath -Parent
    If (!(Test-Path $ParentLogFolder)) {
        New-Item $ParentLogFolder -ItemType Directory
        $cmd = "compact.exe /c /s:$ParentLogFolder"
        CMD /C $cmd
    }
    
    #$LoggingRetentionDays = 90
    #$LoggingRetentionMB = 20
    
    # Calculate the date X days ago
    $ThresholdDate = (Get-Date).AddDays(-$LoggingRetentionDays)
    
    If (Test-Path $LogPath) {
        # Retrieve a list of log files
        $LogFiles = Get-ChildItem -Path $ParentLogFolder | Where-Object { $_.Extension -eq ".log" -and $_.Name -like "*$LogName*" }
        
        # Delete log files older than X days
        $LogFiles | Where-Object { $_.CreationTime -lt $ThresholdDate } | Remove-Item -Force
        
        # Check the size of the current log file and rotate if it exceeds the capacity
        if ((Get-Item $LogPath).Length / 1MB -ge $LoggingRetentionMB) {
            $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $RotatedLogPath = $LogPath -replace "$LogName.log", "$LogName`_$Timestamp.log"
            Rename-Item -Path $LogPath -NewName $RotatedLogPath
            Start-Transcript -path "$LogPath" -append -IncludeInvocationHeader
        }
        else {
            Start-Transcript -path "$LogPath" -append -IncludeInvocationHeader
        }
    }
    else {
        Start-Transcript -path "$LogPath" -append -IncludeInvocationHeader
    }
    #endregion
}
    
function Stop-LoggingRetention {
    try { stop-transcript | out-null }
    catch { }
}

function Get-EncodedString{
    param(
        [string]$InputString
    )
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($InputString)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    # Output the Base64 string
    Return $encodedCommand

}

function Publish-ScheduledTask {
    param(
        [Parameter(Mandatory=$true)]
        $EncodedString,
        [Parameter(Mandatory=$False)]
        [int]$IntervalMinutes = 5,
        [Parameter(Mandatory=$True)]
        [string]$TaskName
        
    )

    #if($User -like '*$'){
        $Action=("C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe")
        $ActionArgument = ("-NoProfile -ExecutionPolicy Bypass -encoded $EncodedString")
        $Actions = New-ScheduledTaskAction -Execute $Action -Argument $ActionArgument
        $Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 365) -Once -At (Get-Date)

        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest


        $TaskCheck = Get-ScheduledTask -TaskName "$TaskName" -ErrorAction SilentlyContinue
        if($TaskCheck) {
            $TaskCheck | Unregister-ScheduledTask -Confirm:$false
        }
        #$Task = New-ScheduledTask -action $Actions -Trigger 
        #$Task = Register-ScheduledTask -TaskName "Automated\$TaskName" -InputObject $task -user $User
        Register-ScheduledTask -TaskName "Automated\$TaskName" -Action $Actions -Trigger $Trigger -Principal $Principal #-Settings $Settings #-Description $Description
        Start-ScheduledTask -TaskName "Automated\$TaskName"

    #}
}

function Get-ServiceUser {
    param(
        $ServiceName

    )
    Return (Get-WMIObject -class Win32_Service |?{$_.Name -eq $ServiceName}).StartName

}

Export-ModuleMember -Function Start-LocalSoftwareInstall, Start-RemoteSoftwareInstall, Grant-ADPermission, Convert-IpAddressToMaskLength, Convert-Subnetmask, Confirm-RunAsAdministrator, Find-Folders,
Get-DiskFree, Get-FileName, Get-ZipFile, Get-CSVFile, Get-SQLFile, Get-FolderPath, Test-PFXImportFile, Copy-File, Start-LoggingRetention, Stop-LoggingRetention, Get-EncodedString, 
Publish-ScheduledTask, Get-ServiceUser