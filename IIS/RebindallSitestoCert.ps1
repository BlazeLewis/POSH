$Websites = Get-Website

$CertPath = "Cert:\LocalMachine\My" #May be "Cert:LocalMachine\WebHosting"

$origin = (Get-ChildItem -path $CertPath -Recurse | ?{$_.Subject -match "CloudFlare Origin"}).Thumbprint 

$CertFolder = $CertPath.split('`\')[-1]

foreach ($WebSite in $Websites){
    $Binding = Get-WebBinding -name $Website.name
    if($Binding.protocol -eq "https"){
        $Binding.RebindSslCertificate("$Origin","$CertFolder")
        (Get-WebBinding -name $Website.name).CertificateHash

    }
}