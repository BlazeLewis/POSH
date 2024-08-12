$Object = @()  #Input Array

$ReturnData =  [System.Collections.ArrayList]@()
foreach ($Object in $Objects) {

    $row = [PsCustomObject]@{
        Name = $Name
        Value = $Value
        Other = $Other
    }
    [void]$ReturnData.Add($row)
}
$ReturnData