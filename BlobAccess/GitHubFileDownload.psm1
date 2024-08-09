
Function Get-GitHubFile {
    param(
        ##Create default paths if needed
        [Parameter(Mandatory=$false)]
        [string]$FilePath = "C:\Temp",
        [Parameter(Mandatory=$false)]
        [uri]$BaseURL = "https://raw.githubusercontent.com/BlazeLewis",
        [Parameter(Mandatory=$false)]
        [string]$Repo = "POSH",
        [Parameter(Mandatory=$false)]
        [string]$Branch = 'main',
        [Parameter(Mandatory=$false)]
        [string]$RepoFolder = "", #Use a / to separate folders (ex. Windows/Utilities)
        [Parameter(Mandatory=$false)]
        [string]$FileName = "SwissArmyKnife.psm1"
    )

    if(!(Test-Path $FilePath)){
        New-Item $FilePath -ItemType Directory
    }


    $uriParts = @($BaseURL, $Repo, $Branch, $RepoFolder, $FileName) | Where-Object { $_ -ne "" } 
    $URI = $uriParts -join "/"

    #Select method of downloading based on OS Version
    if($PSVersion.major -eq 5){
        $FileDownloadCode =  (Invoke-WebRequest -UseBasicParsing -Uri $URI -OutFile "$FilePath\$FileName" -PassThru).statuscode
    }
    if($PSVersion.major -ne 5){
        $FileDownloadCode = (Invoke-WebRequest -Uri $URI -OutFile "$FilePath\$FileName" -PassThru).statuscode
    }
    #Make sure the file isn't blocked on import
    Unblock-File -Path "$FilePath\$FileName" -Confirm:$false
    if($FileDownloadCode -ne 200){
        Return "Failed Download"
        break
    }

    #Import the file if it's a Module ready to use
    if($FileName -like "*.psm1"){
        Import-Module "$FilePath\$FileName"

    }else{

        Write-Host "You can Find your $FileName in: $FilePath\$FileName"
    }

}

Export-ModuleMember -Function Get-GitHubFile