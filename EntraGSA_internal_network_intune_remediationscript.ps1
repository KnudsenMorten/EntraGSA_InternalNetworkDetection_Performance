#------------------------------------------------------------------------------------------------
Write-host "***********************************************************************************************"
Write-host "Entra Private Access | Intune remediation script for 'local access detection'"
Write-host ""
Write-host "Purpose:"
write-host "If connected to internal network, it will suspend Entra Private Access (if running) to force client to do direct connection"
write-host "If NOT connected to internal network, it will start Entra Private Access (if stopped)"
Write-host "***********************************************************************************************"
write-host ""
#------------------------------------------------------------------------------------------------

##################################
# VARIABLES
##################################

<#
    #-----------------------------------------------------------------------------------------------------------------------------------
    # Supported Modes

    #-----------------------------------------------------------------------------------------------------------------------------------
    # Method #1 - DNSName-to-IP - Local DNS Name lookup - result should respond to IP addr
    # NOTE: Requires local DNS solution like Windows AD DNS, InfoBlox, Router DNS, etc.
    #-----------------------------------------------------------------------------------------------------------------------------------

        $Mode                                 = "Resolve_DNSName-Validate_Against_IP"
        $Target                               = "DC1.2linkit.local"
        $ExpectedResult                       = "10.1.0.5"
        $FailoverTargetIP                     = "172.22.0.11"

    #-----------------------------------------------------------------------------------------------------------------------------------
    # Method #2A - IP-to-DNSName - IP address reverse lookup - result should respond to DNS hostname address - use specific DNS server
    # NOTE: This DNS domain cannot be inside Private Access tunnel. Must be an external zone used locally
    #       Reason: Entra Private Access treats any hosts names part of Private DNS-functionality as wildcards, so it will respond with an internal tunnel IP when client is running
    #-----------------------------------------------------------------------------------------------------------------------------------

        $Mode                                 = "Ping_IP-Resolve-to-DNSName"
        $Target                               = "10.1.0.5"
        $ExpectedResult                       = "DC1.2linkit.local"
        $DNSServerIP                          = "10.1.0.5"

    #-----------------------------------------------------------------------------------------------------------------------------------
    # Method #2B - IP-to-DNSName - IP address reverse lookup - result should respond to DNS hostname address - use DNS from IP/DHCP settings on client
    # NOTE: This DNS domain cannot be inside Private Access tunnel. Must be an external zone used locally
    #       Reason: Entra Private Access treats any hosts names part of Private DNS-functionality as wildcards, so it will respond with an internal tunnel IP when client is running
    #-----------------------------------------------------------------------------------------------------------------------------------

        $Mode                                 = "Ping_IP-Resolve-to-DNSName"
        $Target                               = "10.1.0.5"
        $ExpectedResult                       = "DC1.2linkit.local"
        $DNSServerIP                          = $null

    #-----------------------------------------------------------------------------------------------------------------------------------
    # Method #3 - IP-to-MACAddr - Ping IP addr and validate MAC address matches the expected result
    # NOTE: Method can typically only be used when device is on same subnet as target IP device fx. router (switched network)
    #       This method can easily be extended into an array covering all local sites, but it must be manually maintained
    #-----------------------------------------------------------------------------------------------------------------------------------

        $Mode                                 = "Ping_IP-Validate_MACAddr_Against_ARP_Cache"
        $Target                               = "192.168.1.1"
        $ExpectedResult                       = "d2-21-f9-7e-82-86"

#>
    #-----------------------------------------------------------------------------------------------------------------------------------
    # Put you chosen method here below
        $Mode                                 = "Resolve_DNSName-Validate_Against_IP"
        $Target                               = "GSA-TEST.xxxxxx"
        $ExpectedResult                       = "172.22.0.1"
        $FailoverTargetIP                     = "172.22.0.11"


    #-----------------------------------------------------------------------------------------------------------------------------------

    $RegPath                              = "HKCU:\SOFTWARE\EntraGSA_NetworkDetection"
    $RegKey_LastRemediation               = "EntraGSA_RemediationScript_Last_Run"
    $RegKey_SuspendRemediation            = "EntraGSA_SuspendNetworkDetectionRemediation"

    $RegPathSuspendPrivateAccess          = "HKCU:\Software\Microsoft\Global Secure Access Client"
    $RegKeySuspendPrivateAccess           = "IsPrivateAccessDisabledByUser"  # DWORD 0 = Private Access is Active, 1 = Private Access is Suspended

    $RerunEveryMin                        = 1
    $RerunNumberBeforeExiting             = 59 # When it hits the number, it forces script to Exit 1. It must be less than 1 hr, as remediation job kicks off hourly
    $RerunTesting                         = $false  # If $true it wil force script to run every 2 sec. If $False, if uses $RerunEveyMin




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
                    Write-host "Mode  : $($Mode)"
                    write-host ""
                    write-host "Target: $($Target)"
                    Clear-DnsClientCache

                    ################################################
                    # (1) Resolve_DNSName-Validate_Against_IP
                    ################################################

                    If ($Mode -eq "Resolve_DNSName-Validate_Against_IP")
                        {
                            $FailoverActive = $false
                            $DNSCheck = Resolve-DnsName -Name $Target -Type A -ErrorAction SilentlyContinue

                            If ( ($DNSCheck -eq $null) -or ($DNSCheck -eq "") )
                                {
                                    $DNSCheck = [PSCustomObject]@{
                                        IPAddress = "NOT Found"
                                    }

                                    write-host ""
                                    write-host "Failover-mode .... Doing a secondary ping test" -ForegroundColor Yellow

                                    # Failover to try to test using ping
                                    $PingCheck = Test-Connection $FailoverTargetIP -Count 3 -Quiet -ErrorAction SilentlyContinue
                                    $FailoverActive = $true

                                    If ($PingCheck)
                                        {
                                            $LocalNetworkDetected = $true
                                        }
                                    Else
                                        {
                                            $LocalNetworkDetected = $false
                                        }
                                }

                            If (!($FailoverActive))
                                {
                                    write-host ""
                                    Write-host "IP Address (response): $($DNSCheck.IPAddress)"
                                    Write-host "IP Address (expected): $($ExpectedResult)"
                                    write-host ""

                                    If ($DNSCheck.IPAddress -eq $ExpectedResult)
                                        {
                                            $LocalNetworkDetected = $true
                                        }
                                    Else
                                        {
                                            $LocalNetworkDetected = $false
                                        }
                                }
                        }


                    ################################################
                    # (2) Ping_IP-Resolve-to-DNSName
                    ################################################
                    ElseIf ($Mode -eq "Ping_IP-Resolve-to-DNSName")
                        {
                            $PingCheck = Test-Connection $Target -Count 3 -Quiet -ErrorAction SilentlyContinue

                            If ($PingCheck)  # True
                                {
                                    If ($DNSServerIP)
                                        {
                                            $DNSCheck = Resolve-DnsName -Name $Target -Type PTR -Server $DNSServerIP -ErrorAction SilentlyContinue
                                        }
                                    Else
                                        {
                                            $DNSCheck = Resolve-DnsName -Name $Target -Type PTR -ErrorAction SilentlyContinue
                                        }
                                }

                            If ( ($DNSCheck -eq $null) -or ($DNSCheck -eq "") )
                                {
                                    $DNSCheck = [PSCustomObject]@{
                                        IPAddress = "NOT Found"
                                    }
                                }

                            write-host ""
                            Write-host "IP Address (response): $($DNSCheck.NameHost)"
                            Write-host "IP Address (expected): $($ExpectedResult)"
                            write-host ""

                            If ($DNSCheck.NameHost -eq $Target)
                                {
                                    $LocalNetworkDetected = $true
                                }
                            Else
                                {
                                    $LocalNetworkDetected = $false
                                }
                        }

                    ################################################
                    # (3) Ping_IP-Validate_MACAddr_Against_ARP_Cache
                    ################################################
                    ElseIf ($Mode -eq "Ping_IP-Validate_MACAddr_Against_ARP_Cache")
                        {
                            $DNSCheck = Test-Connection $Target -Count 3 -Quiet -ErrorAction SilentlyContinue
                            If ($DNSCheck)  # True
                                {
                                    $ARPCache = Get-NetNeighbor -IncludeAllCompartments -AddressFamily IPv4
                                    If ($ARPCache)
                                        {
                                            $MACAddr = "NOT_FOUND"
                                            $ValidateARPCache = $ARPCache | Where-Object { ($_.IPAddress -eq $Target) }
                                            ForEach ($Entry in $ValidateARPCache)
                                                {
                                                    If ($Entry.IPAddress -eq $Target)
                                                        {
                                                            $MACAddr = $Entry.LinkLayerAddress
                                                        }
                                                }
                                        }

                                    write-host ""
                                    Write-host "IP Address (response): $($MacAddr)"
                                    Write-host "IP Address (expected): $($ExpectedResult)"
                                    write-host ""

                                    If ($MacAddr -eq $ExpectedResult)
                                        {
                                            $LocalNetworkDetected = $true
                                        }
                                    Else
                                        {
                                            $LocalNetworkDetected = $false
                                        }
                                }
                        }


                ########################################################
                # Remediation
                ########################################################

                    ########################################################
                    # Internal network was detected
                    ########################################################
                    If ($LocalNetworkDetected)
                        {
                            Write-host "Computer is connected to internal network" -ForegroundColor Cyan


                            #------------------------------------------------------------------------------------------------------------------------------------
                            # Rollback to v1 method, where the entire GSA client will be turned off. Bug detected, where DNS is not working when only GSA Private Access is turned off !!
                            $GSA_ServiceStatus = Get-Service "GlobalSecureAccessEngineService" -ErrorAction SilentlyContinue

                            If ($GSA_ServiceStatus.Status -eq "Running")
                                {
                                    write-host ""
                                    Write-host "Remediation: Stopping Entra GSA services" -ForegroundColor Yellow
                                    write-host "Check:       Internal network is detected and Entra GSA services was running"
                                    write-host ""

                                    Stop-Service "GlobalSecureAccessTunnelingService" -Force -ErrorAction SilentlyContinue
                                    Stop-Service "GlobalSecureAccessPolicyRetrieverService" -Force -ErrorAction SilentlyContinue
                                    Stop-Service "GlobalSecureAccessManagementService" -Force -ErrorAction SilentlyContinue
                                    Stop-Service "GlobalSecureAccessEngineService" -ErrorAction SilentlyContinue
                                    Clear-DnsClientCache

                                }
                            ElseIf ($GSA_ServiceStatus.Status -eq "Stopped")
                                {
                                    write-host ""
                                    Write-host "Success: Entra GSA services are stopped" -ForegroundColor Green
                                    write-host "Check:   Internal network is detected and Entra GSA services are stopped"
                                    write-host ""
                                }

                            #------------------------------------------------------------------------------------------------------------------------------------
                            <# V2 CODE - NOT WORKING AS DNS IS NOT WORKING WHEN GSA PRIVATE ACCESS IS SUSPENDED !!!

                            $KeyValue = Get-ItemPropertyValue $RegPathSuspendPrivateAccess -Name $RegKeySuspendPrivateAccess -ErrorAction SilentlyContinue

                            If ( ($KeyValue -eq $null) -or ($KeyValue -eq 0) )  # DWORD 0 = Private Access is Active, 1 = Private Access is Suspended
                                {
                                    write-host ""
                                    Write-host "Remediation: Suspending Entra Private Access services" -ForegroundColor Yellow
                                    write-host ""

                                    $Result = New-Item -Path "$($RegPathSuspendPrivateAccess)" -ErrorAction SilentlyContinue
                                    $Result = Set-ItemProperty -Path "$($RegPathSuspendPrivateAccess)"  -Name $RegKeySuspendPrivateAccess -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                }
                            ElseIf ($KeyValue -eq 1)  # Entra Private Access is disabled !!
                                {
                                    write-host ""
                                    Write-host "Success: Entra Private Access is already suspended" -ForegroundColor Green
                                    write-host ""
                                }
                            #>
                            #------------------------------------------------------------------------------------------------------------------------------------
                        }

                    ########################################################
                    # Internal network was NOT detected
                    ########################################################
                    ElseIf (!($LocalNetworkDetected))
                        {
                            Write-host "Computer is NOT connected to internal network" -ForegroundColor Cyan

                            #------------------------------------------------------------------------------------------------------------------------------------
                            # Rollback to v1 method, where the entire GSA client will be turned off. Bug detected, where DNS is not working when only GSA Private Access is turned off !!
                            $GSA_ServiceStatus = Get-Service "GlobalSecureAccessEngineService" -ErrorAction SilentlyContinue

                            If ($GSA_ServiceStatus.Status -eq "Stopped")
                                {
                                    write-host ""
                                    Write-host "Remediation: Starting Entra GSA services" -ForegroundColor Yellow
                                    write-host "Check:       Internal network is NOT detected and Entra GSA services was stopped"
                                    write-host ""

                                    Start-Service "GlobalSecureAccessTunnelingService" -ErrorAction SilentlyContinue
                                    Start-Service "GlobalSecureAccessPolicyRetrieverService" -ErrorAction SilentlyContinue
                                    Start-Service "GlobalSecureAccessManagementService" -ErrorAction SilentlyContinue
                                    Start-Service "GlobalSecureAccessEngineService" -ErrorAction SilentlyContinue

                                    $Result = New-Item -Path "$($RegPathSuspendPrivateAccess)" -ErrorAction SilentlyContinue
                                    $Result = Set-ItemProperty -Path "$($RegPathSuspendPrivateAccess)"  -Name $RegKeySuspendPrivateAccess -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Clear-DnsClientCache
                                }
                            ElseIf ($GSA_ServiceStatus.Status -eq "Running")
                                {
                                    write-host ""
                                    Write-host "Success: Entra GSA services are running" -ForegroundColor Green
                                    write-host "Check:   Internal network is NOT detected and Entra GSA services are already running"
                                    write-host ""
                                }

                            #------------------------------------------------------------------------------------------------------------------------------------
                            <# V2 CODE - NOT WORKING AS DNS IS NOT WORKING WHEN GSA PRIVATE ACCESS IS SUSPENDED !!!

                            $KeyValue = Get-ItemPropertyValue $RegPathSuspendPrivateAccess -Name $RegKeySuspendPrivateAccess -ErrorAction SilentlyContinue

                            If ( ($KeyValue -eq $null) -or ($KeyValue -eq 1) )  # DWORD 0 = Private Access is Active, 1 = Private Access is Suspended
                                {
                                    write-host ""
                                    Write-host "Remediation: Starting Entra Private Access services" -ForegroundColor Yellow
                                    write-host ""

                                    $Result = New-Item -Path "$($RegPathSuspendPrivateAccess)" -ErrorAction SilentlyContinue
                                    $Result = Set-ItemProperty -Path "$($RegPathSuspendPrivateAccess)"  -Name $RegKeySuspendPrivateAccess -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                                }
                            ElseIf ($KeyValue -eq 0)  # Entra Private Access is running !!
                                {
                                    write-host ""
                                    Write-host "Success: Entra Private Access is already running" -ForegroundColor Green
                                    write-host ""
                                }
                            #>
                            #------------------------------------------------------------------------------------------------------------------------------------
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
