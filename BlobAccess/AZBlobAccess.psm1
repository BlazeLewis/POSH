function Import-AZBlobFunctions {
<#
    .SYNOPSIS
    This function is used to import Blob Functions from an Azure URL protected by a SAS Key.  
    This is used to import more detailed or protected scripts from behind an azure auth-wall.
    By default it will download all *.PSM1 files and auto-import them into your current PS Session.
    By default it will store the PSM1 file in C:\Temp

    
    .DESCRIPTION
    Suggested Output use in a script
    Import-AZBlobFunctions -SASURL <SASURLwithKEY> -Path <DestinationPathforFiles> -Filter <StringFilterforModules> -AutoImport <$False/$True(default))
    
#>

    param (
        [Parameter(Mandatory=$True)]
        [string]$SASURL,
        [Parameter(Mandatory=$False)]
        [string]$Path,
        [Parameter(Mandatory=$False)]
        [string]$Filter,
        [Parameter(Mandatory=$False)]
        [boolean]$AutoImport
    )
 #Script needs to invoke this first:
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

    $ReturnData = @()
   
    if(!$Path){
        $RootPath = "C:\Temp"
        if(!(Test-Path $RootPath)){
            New-Item -Path $RootPath -ItemType Directory
        }
        $Path = "$RootPath\PSModule"
    }
    if($AutoImport -ne $False){
        $AutoImport = $True       
    }
    $uri = $SASURL.split('?')[0]
    $sas = $SASURL.split('?')[1]

    $newurl = $uri + "?restype=container&comp=list&" + $sas 
    
    #Invoke REST API
    $body = Invoke-RestMethod -uri $newurl

    #cleanup answer and convert body to XML
    $xml = [xml]$body.Substring($body.IndexOf('<'))

    #use only the relative Path from the returned objects
    if(!$Filter){
        $files = $xml.ChildNodes.Blobs.Blob.Name 
    }
    if($Filter){
        $files = $xml.ChildNodes.Blobs.Blob.Name | Where-Object{$_ -match $Filter}
    }
    #create folder structure and download files
    $files = $files |Where-Object{$_ -like "*.psm1"}

    foreach($File in $Files){ #}
         $FileFix = ($File).replace('/','\')
         $FilePathFixed = (Join-Path $Path $FileFix)
         $FileNameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($FilePathFixed)
         New-Item (Join-Path $Path (Split-Path $FileFix)) -ItemType Directory -ea SilentlyContinue | Out-Null
         Try{
            Remove-Item $FilePathFixed -confirm:$false -ea SilentlyContinue
            Write-Host "Removing $FilePathFixed"
         } Catch {Out-Null}
         (New-Object System.Net.WebClient).DownloadFile($uri + "/" + $File + "?" + $sas, $FilePathFixed)
         $ReturnData = $ReturnData + (Join-Path $Path $File)
         Try{remove-module -name $FileNameNoExt -ea SilentlyContinue}catch{out-null}
        if($File -like "*.psm1" -and $AutoImport -eq $true){import-module -name $FilePathFixed}
    }
    


    Return $ReturnData
    #$files | ForEach-Object { $_; New-Item (Join-Path $Path (Split-Path $_)) -ItemType Directory -ea SilentlyContinue | Out-Null
    #    (New-Object System.Net.WebClient).DownloadFile($uri + "/" + $_ + "?" + $sas, (Join-Path $Path $_))
    # }
}

function Start-AZBlobUploadArchiveLogs {
<#
    .SYNOPSIS
        This function is used to upload Log Files to a "log-archive" container located on Azure using a SASURL.  
        This also stores the data based on the ProductName and the LogType to build out folder structure for the logs.
        

    .DESCRIPTION
        Suggested Output use in a script
        Start-AZBlobUploadArchiveLogs -SASURL <SASURLwithKEY> -ProductName <RootFolderName> -LogType <SubFolderName> -File <PathtoSourceFile>

#>
    param (
        [Parameter(Mandatory=$True)]
        [string]$SASURL,
        [Parameter(Mandatory=$False)]
        [string]$ProductName,
        [Parameter(Mandatory=$True)]
        [string]$File,
        [Parameter(Mandatory=$False)]
        [string]$LogType
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    $Container = "log-archive"
    if(!$ProductName){
        $ProductName = "ProductNotSet"
    }
    if(!$LogType){
        $LogType = "LogNotSet"
    }

    $date = Get-Date -format "MM-dd-yyyy-HHmm_ss"
    
    $uri = $SASURL.split('?')[0]
    $sas = $SASURL.split('?')[1]
    
    #Our source File:
    #$file = "C:\ConfigMgrSetup.log"
    Try{$ServerName = $Env:COMPUTERNAME}Catch{$ServerName = ''}
    Try{$DomainName = $Env:USERDNSDOMAIN}Catch{$DomainName = ''} #-replace '.',"-"
    
    #$env:USERDOMAIN

    $FileInfo = get-item $File
    $FileName = $FileInfo.name
    $FileNameSplit = $FileName.split(".")
    $UploadFileName = $ServerName+"-$DomainName-"+$FileNameSplit[0]+"_$Date."+$FileNameSplit[1]

    
    #The target URL wit SAS Token
    #uri
    #$sas
    $uriPath = "$uri$Container/$ProductName/$LogType/$($UploadFileName)"
    $uribuild = $uriPath +"?"+$Sas 
    #Define required Headers
    $headers = @{ #}
        'x-ms-blob-type' = 'BlockBlob'
    }
    $ReturnData=@{}
    #Upload File...
    Try{
        Invoke-RestMethod -Uri $uribuild -Method Put -Headers $headers -InFile $file 
        $Status = $True
        Write-Host "Upload of $File to $uriPath Successful"
    }Catch{
        Write-Host "Upload of $File to $uriPath Failed"
        $Status = $False
    }
        
        
    $ReturnData  = [ordered]@{
        Success = $Status
        SourceFile = $file
        DestinationFile = $UploadFileName
        DestinationUri = $uriPath
        DestContainer = $Container
    }

    $ReturnData
}

function Start-AZBlobUpload {
<#
    .SYNOPSIS
        This function is used to upload Log Files to a defined container located on Azure using a SASURL.  
        This also stores the data based on the ContainerName/FolderName/SubFolderName to help build structure.
        

    .DESCRIPTION
        Suggested Output use in a script
        Start-AZBlobUpoad -SASURL <SASURLwithKEY> -ContainerName <AZContainerName> -FolderName <MainFolderUnderContainerName> -SubFolderName <SubFoldertoFolder> -File <PathtoSourceFile>

#>
    param (
        [Parameter(Mandatory=$True)]
        [string]$SASURL,
        [Parameter(Mandatory=$True)]
        [string]$ContainerName,
        [Parameter(Mandatory=$True)]
        [string]$FolderName,
        [Parameter(Mandatory=$True)]
        [string]$File,
        [Parameter(Mandatory=$False)]
        [string]$SubFolderName
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

    #$file = "C:\temp\test.txt"
    #$ProductName = "Product"
    #$LogType = "Test"
    
    $Container = $ContainerName.ToLower()
    if(!$FolderName){
        $FolderName = "DefaultFolder"
    }
    #if(!$SubFolderName){
    #    $SubFolderName = ""
    #}
    

    $date = Get-Date -format "MM-dd-yyyy-HHmm_ss"
    
    $uri = $SASURL.split('?')[0]
    $sas = $SASURL.split('?')[1]
    
    #Our source File:
    #$file = "C:\ConfigMgrSetup.log"
    #Try{$ServerName = $Env:COMPUTERNAME}Catch{$ServerName = ''}
    #Try{$DomainName = $Env:USERDNSDOMAIN}Catch{$DomainName = ''} #-replace '.',"-"
    
    $FileInfo = get-item $File
    $FileName = $FileInfo.name
    $FileNameSplit = $FileName.split(".")
    $UploadFileName = $FileNameSplit[0]+"."+$FileNameSplit[1] #$ServerName+"-$DomainName-"+$FileNameSplit[0]+"_$Date."+$FileNameSplit[1]

    #uri
    #$sas
    if(!$SubFolderName){
        $uriPath = "$uri$Container/$FolderName/$($UploadFileName)"
     
    }
    if($SubFolderName){
        $uriPath = "$uri$Container/$FolderName/$SubFolderName/$($UploadFileName)"
    }

    #The target URL with SAS Token
    $uribuild = $uriPath+"?"+$Sas

    #Define required Headers
    $headers = @{
        'x-ms-blob-type' = 'BlockBlob'
    }
    
    #Upload File...
    Try{
        Invoke-RestMethod -Uri $uribuild -Method Put -Headers $headers -InFile $file
        Write-Host "Upload of $File to $uriPath Successful"
        $Status = $True
    }Catch{
        Write-Host "Upload of $File to $uriPath Failed"
        $Status = $False
    }

    $ReturnData  = [ordered]@{
        Success = $Status
        SourceFile = $file
        DestinationFile = $UploadFileName
        DestinationUri = $uriPath
        DestContainer = $Container
    }

    $ReturnData

}

function Get-AZBlobFile {
    <#
        .SYNOPSIS
            This function is used to download Files from a defined container located on Azure using a SASURL made from the CONTAINER, not Storage Account.
            Needs Read,List only.  SASURL must contain the container name.  
            This also stores the data based on the ContainerName/FolderName/SubFolderName to help build structure.
            
    
        .DESCRIPTION
            Suggested Output use in a script
            This below command will direct download a file however the full heirarchy of the file must be used in the format (/FileFolder/SubFolder/FileName.ext)
                Get-AZBlobFile -SASURL <SASURLwithKEY> -Filter </FileFolder/SubFolder/FileName.Ext>

            Searching is supported however it is an expensive operation, it should be limited on use and storage of files should be able to be derived easily for automation
                Get-AZBlobFile -SASURL <SASURLwithKEY> -Filter "Keyword"

    #>

    param (
        [Parameter(Mandatory=$True)]
        [string]$SASURL,
        [Parameter(Mandatory=$False)]
        [string]$Path,
        [Parameter(Mandatory=$True)]
        [string]$Filter,
        [Parameter(Mandatory=$False)]
        [string]$Limit,
        [Parameter(Mandatory=$False)]
        [boolean]$ConfirmExpensive=$True
    )
    
    if(!$Filter){
        Write-Host "Search set without a Filter.  Stopping" -BackgroundColor Red -ForegroundColor Black
        break
    }
    <#
    if($Search -eq $False -and $Filter -notmatch "^(\/[^\/]+)+\/([\w\s.-]+\.[\w.-]+)$"){ #  (Extension Filter using / in the path)
        Write-Host "Specific File Path not Set.  Search not enabled.
        If not using -Search=`$False then you will need to define an absolute file name and path. ex. /Folder/version/file.ext
        Using:$Filter as the path, must inclue 1 sub-directory and a filename with an extension.
        Stopping." -BackgroundColor Red -ForegroundColor Black
        break
    }
    #>

    if($Filter -notmatch "^(\/[^\/]+)+\/([\w\s.-]+\.[\w.-]+)$") {
        Write-Host "Search Enabled, Using Filter:$Filter" -BackgroundColor Yellow -ForegroundColor Black
        $DirectFilter = $false
    }
    
    if($Filter -match "^(\/[^\/]+)+\/([\w\s.-]+\.[\w.-]+)$"){   #"^(\/[^\/]+)+\/([\w\s.-]+\.[\w.-]+)$" (Extension Filter using / in the path
        $DirectFilter = $true
        Write-Host "DirectToFile Detected." -BackgroundColor Green -ForegroundColor Black
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

    $ReturnData = @()
    if(!$Limit){
        $Limit = 1
    }
    if($Limit -gt 50){
        Write-Host "Hard limit of 50 Files, Stopping."
        Break
    }

    if(!$Path){
        $RootPath = "C:\Temp"
        if(!(Test-Path $RootPath)){
            New-Item -Path $RootPath -ItemType Directory
        }
        $Path = "$RootPath"
    }
    if($AutoImport -ne $False){
        $AutoImport = $True       
    }
    $uri = $SASURL.split('?')[0]
    $sas = $SASURL.split('?')[1]

    if($DirectFilter -eq $False){
        Write-Host "Searching is an EXPENSIVE operation and should be limited on use" -BackgroundColor Yellow -ForegroundColor Black
        if($ConfirmExpensive -ne $False){
            Write-Host "Pausing for you to verify the expensive operation."
            Pause
        }
        $newurl = $uri + "?restype=container&comp=list&" + $sas 
    }
 
    ##If this is a direct file, then the file can be directly downloaded without any other real processing
    #if($Search -eq $false -and $Filter -match "^(\/[^\/]+)+\/([\w\s.-]+\.[\w.-]+)$") {   #"^(\/[^\/]+)+\/([\w\s.-]+\.[\w.-]+)$" (Extension Filter using / in the path, backed up
    if($DirectFilter -eq $True) { 
        Write-Host "DirectToFile being Used: $Filter" -BackgroundColor Green -ForegroundColor Black
        $newurl = $uri+$filter+"?"+$sas
            
        $File = $newurl
        $FileFixSlash = ($Filter).replace('/','\')
        $FileFix = $FileFixSlash.split('\')[-1]
        $FilePathFixed = (Join-Path $Path $FileFix)
        Try{
            Remove-Item $FilePathFixed -confirm:$false -ea SilentlyContinue
            Write-Host "Removing $FilePathFixed"
        } Catch {Out-Null}
        Write-Host "Downloading $uri$filter to $FilePathFixed"
        (New-Object System.Net.WebClient).DownloadFile($File, $FilePathFixed)
        $ReturnData = $ReturnData + $FilePathFixed
        #Return $ReturnData
        #break

    }


    if($DirectFilter -eq $false){
    ##If the file is not a direct file, then lots of formating and parsing are needed.
        $ContainerTest = $uri.split('/')[3]
        if(!$ContainerTest){
            Write-Host "Container not found, please use SASURL with the Container in path.
    If using Storage Account SAS, it will need to be generated on the Container instead.
    Path Used: $uri" -BackgroundColor Yellow -ForegroundColor Black
        }
    #Invoke REST API
    $PSVersion = $PSVersionTable.PSVersion

    #Enable -UseBasicParsing when available
    if($PSVersion.major -eq 5){
        $body = Invoke-RestMethod -Method Get -uri $newurl -UseBasicParsing
    }else{
        $body = Invoke-RestMethod -Method Get -uri $newurl
    }
    #cleanup answer and convert body to XML
    $xml = [xml]$body.Substring($body.IndexOf('<'))

    ##If using Search, it must pull all files into PS and Parse the Data for downloading multiple files
       
        #$xml = [xml]$body.Substring($body.IndexOf('<'))

        #use only the relative Path from the returned objects
        if(!$Filter){
            $files = $xml.ChildNodes.Blobs.Blob.Name 
        }
        if($Filter){
            $files = $xml.ChildNodes.Blobs.Blob.Name | Where-Object{$_ -match $Filter}
        }

        if($files.count -gt $Limit){
            Return "File Limit Reached.  Found: "+$files.count+" Files, but Limit of: $Limit.  Stopping!"
            Break
        }

        if($files.count -eq 0){
            Return "File Not Found"
            Break
        }

        #create folder structure and download files
        #$files = $files |?{$_ -like "*.psm1"}
    
        foreach($File in $Files){ #}
            $FileFixSlash = ($File).replace('/','\')
            $FileFix = $FileFixSlash.split('\')[-1]
            $FilePathFixed = (Join-Path $Path $FileFix)
            #$FileNameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($FilePathFixed)
            #New-Item (Join-Path $Path (Split-Path $FileFix)) -ItemType Directory -ea SilentlyContinue | Out-Null
            Try{
                Remove-Item $FilePathFixed -confirm:$false -ea SilentlyContinue
                Write-Host "Removing $FilePathFixed"
            } Catch {Out-Null}
            Write-Host "Downloading $uri/$File to $FilePathFixed"
            (New-Object System.Net.WebClient).DownloadFile($uri + "/" + $File + "?" + $sas, $FilePathFixed)
            $ReturnData = $ReturnData + $FilePathFixed
            
            #Try{remove-module -name $FileNameNoExt -ea SilentlyContinue}catch{out-null}
            #if($File -like "*.psm1" -and $AutoImport -eq $true){import-module -name $FilePathFixed}
        }
    }
    
     Return $ReturnData
}

Export-ModuleMember -function Import-AZBlobFunctions, Start-AZBlobUploadArchiveLogs, Start-AZBlobUpload, Get-AZBlobFile
