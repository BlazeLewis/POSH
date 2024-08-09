# POSH
![ascreenshot](POSH.png)
Handy PowerShell Scripts, Functions and Modules


Using these modules and scripts is pretty straight forward.  One thing to consider is automating downloads of these files using the bulk storage option.  There are different things to do when considering different types of scripts such as simple PS1 or PSM1 files.  These are a bit diffferent to address but here is a script to help you get these items.

```powershell
##Create default paths if needed
$FilePath = "C:\Temp"  ##Place you want it Saved locally
#Enter your URL
$BaseURL = "https://raw.githubusercontent.com/BlazeLewis"
$Repo = "POSH"
$RepoFolder = "" #Use a / to separate folders (ex. Windows/Utilities)
$FileName = "SwissArmyKnife.psm1"




if(!(Test-Path $FilePath)){
    New-Item $FilePath -ItemType Directory
}

$rawURI = 'main'
$uriParts = @($BaseURL, $Repo, $rawURI, $RepoFolder, $FileName) | Where-Object { $_ -ne "" } 
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

