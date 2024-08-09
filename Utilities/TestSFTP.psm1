function Test-SFTP {
 <#
        .SYNOPSIS
            This function is used to clear old Uptime Robot Maintenance Windows created by CWA/Automation, change out the '@<parameter>@' to use common varialbe
            
    
        .DESCRIPTION
            Suggested Output use in a script
            This below command will 
    #>
param(
    [Parameter(Mandatory=$true)]
    [string]$SFTPSiteURL,
    [Parameter(Mandatory=$false)]
    [string]$SFTPUserName = '@SFTPTestUserAccount@',
    [Parameter(Mandatory=$false)]
    [string]$SFTPPass = '@SFTPTestUserPW@',
    [Parameter(Mandatory=$true)]
    [String]$SFTPPort
)
    [int]$SFTPPort = $SFTPPort
    #Script needs to invoke this first:
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $BasePath = "C:\Temp\WinSCP"
    if(!(test-Path $BasePath)){
        New-Item $BasePath -ItemType Directory
    }
    $PSVersion = $PSVersionTable.PSVersion
    $FileURL = 'https://github.com/BlazeLewis/POSH/Utilities/SupportFiles/WinSCP'

    $FileTest = @('WinSCPnet.dll','WinSCP.exe')

    ##Download if Needed
    foreach($File in $FileTest){ #}
        if(!(test-Path "$BasePath\$File")){
            if($PSVersion.major -eq 5){
                $FileDownloadCode = (Invoke-WebRequest -UseBasicParsing -Uri "$FileURL/$File" -OutFile "$BasePath\$File" -PassThru).statuscode
            }else{
                $FileDownloadCode = (Invoke-WebRequest -Uri "$FileURL/$File" -OutFile "$BasePath\$File" -PassThru).statuscode
            }
            Unblock-File -Path "$BasePath\$File" -Confirm:$false
            if($FileDownloadCode -ne 200){
                Return "Failed Download"
                break
            }
        }
    }

    $directory = $null

    # Load WinSCP .NET assembly
    Add-Type -Path "$BasePath\WinSCPnet.dll"
    
    # Set session options
    $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::Sftp
        HostName = $SFTPSiteURL
        UserName = $SFTPUserName
        Password = $SFTPPass
        SshHostKeyPolicy = "AcceptNew"
        PortNumber = $SFTPPort
    }
    

    try{
        # Create session and connect
        $session = New-Object WinSCP.Session
        
        $session.Open($sessionOptions)
    } catch {
        return "failed"
    }
    
    # List directory contents
    $directory = $session.ListDirectory("/")
    
    # Disconnect session
    $session.Dispose()
    
    
    # Check if directory contents are listed
    if ($directory.Count -gt 0) {
        # If directory has contents, return true
        return "success"
    
    } else {
        # If directory is empty, return false
        return "failed"
    
    }
}

Export-ModuleMember -Function Test-SFTP