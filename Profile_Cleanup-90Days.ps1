#This function creates a variable of well known SIDs to be excluded from deletion.
function Test-IsWellKnownSid {

    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSChildName')]
        [string[]] $Sid
    )

    begin {
        $wellKnownSids = [Enum]::GetValues([Security.Principal.WellKnownSidType])
    }

    process {
        foreach ($inputSid in $Sid) {
            try {
                $sidObj = [Security.Principal.SecurityIdentifier]::new($inputSid)
                [bool] ($wellKnownSids.Where({ $sidObj.IsWellKnown($_) }).Count)
            } catch {
                $PSCmdlet.WriteError($_)
            }
        }
    }
}

#Clear out the varialbe SIDsToDelete if previously ran.
Remove-Variable sidsToDelete -ErrorAction SilentlyContinue

#Pulls a list of profiles from the registry. Excludes S-1-5-80 profiles as those are linked to service accounts.
$profiles = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -Exclude 'S-1-5-80*'

#This filters out well known SIDs from the profiles gathered from the registry.
$profilesFiltered = $profiles | Where-Object { !(Test-IsWellKnownSid -Sid $_.PSChildName) }

#This loop goes through each profile in the profile list, adding any profile not signed-in in 90 days to be removed.
#This uses the LocalProfileLoadTime attribute to determine the last login date.
$sidsToDelete = foreach ($p in $profilesFiltered) {
    $loadTime = if ($null -notin $p.LocalProfileLoadTimeHigh, $p.LocalProfileLoadTimeLow) {
        [datetime]::FromFileTime(('0x{0:X8}{1:X8}' -f $p.LocalProfileLoadTimeHigh, $p.LocalProfileLoadTimeLow))
    }
    
    if ($loadTime -lt (Get-Date).AddDays(-90)) {
        # Loadtime is null or greater than 90 days ago
        $p.PSChildName # This creates the SID string list and adds its to variable $SIDsToDelete
    }

}

#This loops through all the SIDs in $SIDsToDelete and deletes the associated profiles from the computer.
foreach ($SID in $SIDsToDelete) {
    $Profilez = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.Special -eq $false -and $_.SID -eq $SID}
if ($Profilez) {
    Remove-CimInstance -InputObject $Profilez
    }
}
