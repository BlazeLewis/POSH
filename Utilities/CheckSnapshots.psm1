function Get-ShadowCopyHistory {
    param (
        [int]$Days = 1
    )

    # Calculate the history date
    $History = (Get-Date).AddDays(-$Days)

    # Get shadow copies, providers, and volumes
    $Shadows = Get-WmiObject Win32_ShadowCopy
    $Providers = Get-WmiObject Win32_ShadowProvider
    $VolumeList = [System.Collections.ArrayList]@()
    $Volumes = Get-WmiObject win32_volume -property DeviceID, Name

    function Convert-CustomDateTime {
        param (
            [string]$datetimeString
        )

        # Extract date and time components
        $date = $datetimeString.Substring(0, 8)  # YYYYMMDD
        $time = $datetimeString.Substring(8, 6)  # HHMMSS
        $fractionalSeconds = $datetimeString.Substring(15, 6)  # sssss
        $timezoneOffset = $datetimeString.Substring(21)  # ±ZZZ

        # Convert to DateTime object
        $formattedDateTime = "{0}-{1}-{2}T{3}:{4}:{5}.{6}" -f `
            $date.Substring(0, 4), `
            $date.Substring(4, 2), `
            $date.Substring(6, 2), `
            $time.Substring(0, 2), `
            $time.Substring(2, 2), `
            $time.Substring(4, 2), `
            $fractionalSeconds

        # Parse the DateTime
        $dateTime = [DateTime]::ParseExact($formattedDateTime, "yyyy-MM-ddTHH:mm:ss.ffffff", $null)

        # Calculate the offset in hours
        $offsetHours = [int]($timezoneOffset / 60)
        $offsetMinutes = [int]($timezoneOffset % 60)

        # Adjust DateTime for the timezone offset
        $dateTime = $dateTime.AddHours(-$offsetHours).AddMinutes(-$offsetMinutes)

        return $dateTime
    }

    $rows = [System.Collections.ArrayList]@()

    foreach($v in $Volumes) {
        $row = [PsCustomObject]@{
            DeviceID = $v.DeviceID
            Name = $v.Name
            Drive = $v.Name
        }
        [void]$VolumeList.Add($row)
    }

    foreach($Shadow in $Shadows) {
        $ShadowDate = Convert-CustomDateTime $Shadow.installDate
        
        if ($ShadowDate -lt $History) {
            [string]$ShadowVolumeGUID = ((($Shadow.VolumeName.Replace('\',"") ).Replace('?Volume','') ).Replace('{','')).Replace('}','')
            foreach($Volume in $Volumes) {
                $VolumeGUID = ((($Volume.DeviceID.Replace('\',"") ).Replace('?Volume','') ).Replace('{','')).Replace('}','')
                if ($VolumeGUID -eq $ShadowVolumeGUID) {
                    $row = [PsCustomObject]@{
                        Computer = $env:COMPUTERNAME
                        VolumeName = $Volume.Name
                        ShadowDate = $ShadowDate
                    }
                    [void]$rows.add($row)
                }
            }
        }
    }
    return $rows
}

Export-ModuleMember -Function Get-ShadowCopyHistory