#------------------------------------------------------------------------------------------------
Write-host "***********************************************************************************************"
Write-host "Entra Private Access | Intune remediation script for 'local access detection'"
Write-host ""
Write-host "Purpose:"
Write-host "If client can do specific NSLOOKUP for internal DNS record, it is connected to internal network"
write-host ""
write-host "If connected to internal network, it will stop Entra GSA services (if running) to force client to do direct connection"
write-host "If NOT connected to internal network, it will start Entra GSA services (if stopped)"
Write-host "***********************************************************************************************"
write-host ""
#------------------------------------------------------------------------------------------------

##################################
# VARIABLES
##################################

    $Internal_DNSRecord_Name              = "<put in your DNS record here>"
    $Internal_DNSRecord_Expected_Response = "<put in the expected IPv4 address here>"

    $RegPath                              = "HKLM:\SOFTWARE\EntraGSA_NetworkDetection"
    $RegKey_LastRemediation               = "EntraGSA_RemediationScript_Last_Run"
    $RegKey_SuspendRemediation            = "EntraGSA_SuspendNetworkDetectionRemediation"

    $RerunEveryMin                        = 1
    $RerunNumberBeforeExiting             = 59 # When it hits the number, it forces script to Exit 1. It must be less than 1 hr, as remediation job kicks off hourly
    $RerunTesting                         = $False  # If $true it wil force script to run every 2 sec. If $False, if uses $RerunEveyMin

##################################
# MAIN PROGRAM
##################################

$RunFrequency = 1

While ($RunFrequency -le $RerunNumberBeforeExiting)
{

    # here we check if the script should be suspended - typically caused by a rougue detection or user wants to manually override
    $SuspendStatusKey = Get-ItemProperty -Path $RegPath -Name $RegKey_SuspendRemediation -ErrorAction SilentlyContinue

    # Key found - checking value
    If ($SuspendStatusKey)
        {
            $SuspendStatusValue = Get-ItemPropertyValue -Path $RegPath -Name $RegKey_SuspendRemediation -ErrorAction SilentlyContinue
        }

        If ( ($SuspendStatusKey -eq $null) -or ($SuspendStatusKey -eq "") -or ($SuspendStatusValue -eq 0) )
            {
                ########################################################
                # Initial check
                ########################################################

                    # Checking DNS record
                    Write-host "Script run frequency (loop): $($RunFrequency) / $($RerunNumberBeforeExiting)"
                    write-host ""
                    Write-host "Checking DNS lookup for $($Internal_DNSRecord_Name)"
                    Clear-DnsClientCache
                    $DNSCheck = Resolve-DnsName -Name $Internal_DNSRecord_Name -Type A -ErrorAction SilentlyContinue

                    If ( ($DNSCheck -eq $null) -or ($DNSCheck -eq "") )
                        {
                            $DNSCheck = [PSCustomObject]@{
                                IPAddress = "NOT Found"
                            }
                        }

                    write-host ""
                    Write-host "IP Address (response): $($DNSCheck.IPAddress)"
                    Write-host "IP Address (expected): $($Internal_DNSRecord_Expected_Response)"
                    write-host ""


                ########################################################
                # Remediation
                ########################################################

                    ########################################################
                    # Internal network was detected
                    ########################################################
                    If ($DNSCheck.IPAddress -eq $Internal_DNSRecord_Expected_Response)
                        {
                            Write-host "Computer is connected to internal network" -ForegroundColor Cyan

                            $GSA_ServiceStatus = Get-Service "GlobalSecureAccessTunnelingService" -ErrorAction SilentlyContinue

                            If ($GSA_ServiceStatus.Status -eq "Running")
                                {
                                    write-host ""
                                    Write-host "Remediation: Stopping Entra GSA services" -ForegroundColor Yellow
                                    write-host "Check:       Internal network is detected and Entra GSA services was running"
                                    write-host ""

                                    Stop-Service "GlobalSecureAccessTunnelingService" -Force -ErrorAction SilentlyContinue
                                    Stop-Service "GlobalSecureAccessPolicyRetrieverService" -Force -ErrorAction SilentlyContinue
                                    Stop-Service "GlobalSecureAccessManagementService" -Force -ErrorAction SilentlyContinue
                                }
                            ElseIf ($GSA_ServiceStatus.Status -eq "Stopped")
                                {
                                    write-host ""
                                    Write-host "Success: Entra GSA services are stopped" -ForegroundColor Green
                                    write-host "Check:   Internal network is detected and Entra GSA services are stopped"
                                    write-host ""
                                }
                        }

                    ########################################################
                    # Internal network was NOT detected
                    ########################################################
                    ElseIf ($DNSCheck.IPAddress -ne $Internal_DNSRecord_Expected_Response)
                        {
                            Write-host "Computer is NOT connected to internal network" -ForegroundColor Cyan

                            $GSA_ServiceStatus = Get-Service "GlobalSecureAccessTunnelingService" -ErrorAction SilentlyContinue

                            If ($GSA_ServiceStatus.Status -eq "Stopped")
                                {
                                    write-host ""
                                    Write-host "Remediation: Starting Entra GSA services" -ForegroundColor Yellow
                                    write-host "Check:       Internal network is NOT detected and Entra GSA services was stopped"
                                    write-host ""

                                    Start-Service "GlobalSecureAccessTunnelingService" -ErrorAction SilentlyContinue
                                    Start-Service "GlobalSecureAccessPolicyRetrieverService" -ErrorAction SilentlyContinue
                                    Start-Service "GlobalSecureAccessManagementService" -ErrorAction SilentlyContinue
                                }
                            ElseIf ($GSA_ServiceStatus.Status -eq "Running")
                                {
                                    write-host ""
                                    Write-host "Success: Entra GSA services are running" -ForegroundColor Green
                                    write-host "Check:   Internal network is NOT detected and Entra GSA services are already running"
                                    write-host ""
                                }
                        }


                    ########################################################
                    # Finalizing - Logging
                    ########################################################
                        # Create initial reg-path stucture in registry
                          If (-not (Test-Path $RegPath))
                              {
                                  $Err = New-Item -Path $RegPath -Force | Out-Null
                              }

                        # Set last run value in registry
                          $Now = (Get-date)
                          $Result = New-ItemProperty -Path $RegPath -Name $RegKey_LastRemediation -Value $Now -PropertyType STRING -Force | Out-Null

                    ########################################################
                    # Loop & Wait
                    ########################################################
                        # increase the $RunFrequency by +1
                        $RunFrequency = 1 + $RunFrequency

                        If ($RerunTesting -eq $true)
                            {
                                write-host ""
                                Write-host "Sleeping for 2 seconds ... please wait !"
                                write-host ""
                                write-host "--------------------------------------------------"
                                write-host ""

                                Start-Sleep -Seconds 2
                            }
                        Else
                            {
                                $SleepSeconds = $RerunEveryMin * 60
                                write-host ""
                                Write-host "Sleeping for $($RerunEveryMin) min. ... please wait !"
                                write-host ""
                                write-host "--------------------------------------------------"
                                write-host ""

                                Start-Sleep -Seconds $SleepSeconds
                            }

            } # If ( ($SuspendStatus -eq $null) -or   ($SuspendStatus -eq "") -or ($SuspendStatus -eq 0) )
        Else
            {
                write-host ""
                Write-host "Suspending script as suspend-key was detected .... exiting script !"
                Exit 0   # Terminated due to suspend key was detected
            }

} # While ($RunFrequency -le $RerunNumberBeforeExiting)

# Tell Intune script has terminated succesfully, when it has reached the rerun-number
  Exit 0
