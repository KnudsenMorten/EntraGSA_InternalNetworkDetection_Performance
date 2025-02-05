#------------------------------------------------------------------------------------------------
Write-host "***********************************************************************************************"
Write-host "Entra Private Access | Intune detection script for internal network detection"
Write-host ""
Write-host "Purpose:"
Write-host "This script will always do Exit 1, as the required checks exists in the remediation script"
write-host ""
Write-host "Basically this script will serve as a scheduled task that runs every 1 hour (remediation frequency)"
Write-host "***********************************************************************************************"
write-host ""
#------------------------------------------------------------------------------------------------

##################################
# VARIABLES
##################################

    $RegPath                              = "HKCU:\SOFTWARE\EntraGSA_NetworkDetection"
    $RegKey_LastDetection                 = "EntraGSA_DetectionScript_Last_Run"


##################################
# MAIN PROGRAM
##################################

    # Create initial reg-path stucture in registry
        If (-not (Test-Path $RegPath))
            {
                $Err = New-Item -Path $RegPath -Force | Out-Null
            }

    #  Set last run value in registry
        $Now = (Get-date)
        $Result = New-ItemProperty -Path $RegPath -Name $RegKey_LastDetection -Value $Now -PropertyType STRING -Force | Out-Null

    # We force Intune detection script to disable to force remediation script to run, where we have the checks
        Exit 1
