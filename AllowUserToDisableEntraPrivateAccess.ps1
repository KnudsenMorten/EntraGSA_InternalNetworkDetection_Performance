<#
##############################################################################
# Allow User to Disable Entra Private Access feature manually (local machine)

0 = User is allowed to start/stop Entra Private Access

1 or no key = User is not allowed to control stop/start
##############################################################################
#>

$Path      = "HKLM:\Software\Microsoft\Global Secure Access Client"
$Key       = "HideDisablePrivateAccessButton" 
$KeyFormat = "Dword"
$Value     = "0"

# Create path if not found
if (!(Test-Path $Path))
    {
        New-Item -Path $Path -Force
    }

Try
    {
        $KeyStatus = Get-ItemPropertyValue -Path $Path -Name $Key -ErrorAction SilentlyContinue
    }
Catch
    {
        # Create key
        Set-ItemProperty -Path $Path -Name $Key -Value $Value -Type $KeyFormat
    }

if ($KeyStatus)
    {
        # change value when already found
        Set-ItemProperty -Path $Path -Name $Key -Value $Value
    }
