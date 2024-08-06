#------------------------------------------------------------------------------------------------
Write-host "***********************************************************************************************"
Write-host "Entra Private Access | Suspend Intune remediation script for 'local access detection'"
Write-host ""
Write-host "Purpose:"
Write-host "This script sets key to suspend the remediation script that controls the Entra GSA stop/start behavior"
Write-host "***********************************************************************************************"
write-host ""
#------------------------------------------------------------------------------------------------

    $RegPath                    = "HKCU:\SOFTWARE\EntraGSA_NetworkDetection"
    $RegKey_SuspendRemediation  = "EntraGSA_SuspendNetworkDetectionRemediation"

    $SuspendStatusValue         = 1   # 0=disable script suspension - 1=enable script suspension

    write-host "Setting the suspend-key to $($SuspendStatusValue)"

    $Result = New-ItemProperty -Path $RegPath -Name $RegKey_SuspendRemediation -Value $SuspendStatusValue -PropertyType DWORD -Force | Out-Null

