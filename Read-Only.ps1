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

#Pulls a list of profiles from the registry. Excludes S-1-5-80 profiles as those are linked service accounts.
$profiles = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -Exclude 'S-1-5-80*'

#This filters out well known SIDs from the profiles gathered from the registry.
$profilesFiltered = $profiles | Where-Object { !(Test-IsWellKnownSid -Sid $_.PSChildName) }

#This loop goes through each profile in the profile list, adding any profile not signed-in in 90 days to be removed.
#This uses the LocalProfileLoadTime attribute to determine the last login date.
$sidsToDelete = foreach ($p in $profilesFiltered) {
    $loadTime = if ($null -notin $p.LocalProfileLoadTimeHigh, $p.LocalProfileLoadTimeLow) {
        [datetime]::FromFileTime(('0x{0:X8}{1:X8}' -f $p.LocalProfileLoadTimeHigh, $p.LocalProfileLoadTimeLow))
    }
    
    try {
        $objUser = (New-Object System.Security.Principal.SecurityIdentifier($p.PSChildName)).Translate([System.Security.Principal.NTAccount]).value
    } catch {
        $objUser = "[UNKNOWN]"
    }
##This creates a custom object to display more details about what will be deleted. We might include this later
    [pscustomobject][ordered]@{
        User = $objUser
        Loadtime = $LoadTime
        SID = $p.PSChildName
    } | Where-Object {($_.Loadtime -lt (Get-Date).AddDays(-90))}

}

$sidsToDelete