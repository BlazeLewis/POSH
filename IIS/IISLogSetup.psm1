function Start-IISLogConfig {
    <#
        .SYNOPSIS
        This function is used to Setup full logging on all IIS Websites on a Server
    
        
        .DESCRIPTION
        Suggested Output use in a script
        
    #>
    
        param (
            [Parameter(Mandatory=$False)]
            [boolean]$CloudFlareSupport=$True
        )

    
    Import-Module Webadministration

    #Set the fields to log to be everything other than Cookies
    $fields = "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Referer,ProtocolVersion,Host,HttpSubStatus"
    $fieldsProp = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logExtFileFlags"
    if ($fieldsProp)
    {
        Write-Host "Fields property exists"
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logExtFileFlags" -value $fields 
    } 
    else
    {
        Write-Host "Fields property doesn't exist"
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logExtFileFlags" -value $fields 
    }



    #Set the custom fields to include x-forwarded-for
    if($CloudFlareSupport -eq $True) {
        $custFieldsProp = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "."
        if ($custFieldsProp) 
        {
            Write-Host "CustomFields property exists"
            Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='x-forwarded-for';sourceName='x-forwarded-for';sourceType='RequestHeader'}
        }
        else {
            Write-Host "CustomFields property doesn't exist"
            Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='x-forwarded-for';sourceName='x-forwarded-for';sourceType='RequestHeader'}
        } 
    }

}

Export-ModuleMember -Function Start-IISLogConfig