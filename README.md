# POSH
Handy PowerShell Scripts, Functions and Modules


Using these modules and scripts is pretty straight forward.  One thing to consider is automating downloads of these files using the bulk storage option.  There are different things to do when considering different types of scripts such as simple PS1 or PSM1 files.  These are a bit diffferent to address but here is a script to help you get these items.

##Create default paths if needed
$FilePath = "C:\Temp"
if(!(Test-Path $FilePath)){
    New-Item $FilePath -ItemType Directory
}

#Enter your URL
$BaseURL = "https://github.com/BlazeLewis"
$Repo = "POSH"
$RepoFolder = ""
$FileName = "SwissArmyKnife.PSM1"

$uriParts = @($BaseURL, $Repo, $RepoFolder, $FileName) | Where-Object { $_ -ne "" }
$URI = $uriParts -join "/"

#Select method of downloading based on OS Version
if($PSVersion.major -eq 5){
    $FileDownloadCode =  (Invoke-WebRequest -UseBasicParsing -Uri "$FileURL/$File" -OutFile "$FilePath\$File" -PassThru).statuscode
}
if($PSVersion.major -ne 5){
    $FileDownloadCode = (Invoke-WebRequest -Uri "$FileURL/$File" -OutFile "$FilePath\$File" -PassThru).statuscode
}
#Make sure the file isn't blocked on import
Unblock-File -Path "$BasePath\$File" -Confirm:$false
if($FileDownloadCode -ne 200){
    Return "Failed Download"
    break
}

#Import the file if it's a Module ready to use
if($FileName -like "*.PSM1"){
    Import-Module "$FilePath\$File"

}else{

    Write-Host "You can Find your $FileName in: $FilePath\$File"
}

