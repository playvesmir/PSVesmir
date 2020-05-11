#Predefined Vars
$autoLoginUser = "Administrator" #Username to be used in autologin (AWS uses Administrator)

#Common Utility Module START
function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    $tempPath = Join-Path $parent $name
    Write-Verbose "New Temp Folder: $tempPath"
    New-Item -ItemType Directory -Path $tempPath
}

#Cleanup
function Remove-TemporaryDirectory($path) {

    While ( Test-Path($path) ){
        Try{
            Remove-Item -Path $path -Force -Recurse -ErrorAction Stop
        }catch{
            Write-Warning "Clean up: File locked, trying again in 5"
            Start-Sleep -seconds 5
        }
    }
    Write-Host "The royal penis is clean, your highness!"
}

function __Test-RegistryValue {
    # https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-value.html
    #This specifies parameters for this function
    param ([parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path, [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value)
    
    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}
#Common Utility Module END

function Install-SSM {
    Write-Host "Installing AWS SSM"
    (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe", "$path\SSMAgent_latest.exe") | Unblock-File
    Start-Process -FilePath "$path\SSMAgent_latest.exe" -ArgumentList "/S"
}

function Install-Chocolatey {
    Write-Host "Installing Chocolatey"
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco feature enable -n allowGlobalConfirmation
}

function Install-Base {
    Write-Host "Installing Devcon"
    cinst devcon.portable

    Write-Host "Installing Chrome"
    cinst googlechrome --ignore-checksums
    
    #Stuff for old games here
    Write-Host "Installing DirectX Redist 2010"
    cinst directx

    Write-Host "Installing Direct Play"
    Install-WindowsFeature Direct-Play | Out-Null
    
    Write-Host "Installing .Net 3.5"
    Install-WindowsFeature Net-Framework-Core | Out-Null
}

#set update policy
function Disable-Updates {
    Write-Host "Disabling Windows Update"
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}
}
    
#Sets all applications to force close on shutdown
function Set-RegistryForceCloseApps 
{
    Write-Host "Enabling Force Closure of Apps on Shutdown"
    if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) 
    {
        Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
    }
    Else 
    {
        New-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
    }
}

#disable new network window - a popup that windows does when it detects "new networks"
function Disable-NewNetworkWindow {
    Write-Host "Disabling New Network Window"
    if((__Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}
}

#disable logout start menu
function Disable-Logout {
    Write-Host "Disabling Logout"
    if((__Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
}

#disable lock start menu
function Disable-Lock {
    Write-Host "Disable Lock"
    if((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
    if((__Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}
}
    
#set automatic time and timezone
function Set-Time {
    Write-Host "Setting Time to Automatic"
    Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null
}

#Disables Server Manager opening on Startup
function Disable-ServerManager {
    Write-Host "Disable Auto Opening Server Manager"
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

#Disable Devices
function Disable-Devices {
    Write-Host "Disabling not required devices"
    devcon64 /r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"
    Get-PnpDevice| where {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice| where {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    devcon64 /r disable "PCI\VEN_1013&DEV_00B8*"
}

function Install-Parsec
{
    Write-Host "Installing Parsec"
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "$path\parsec-windows.exe") | Unblock-File
    & $path\parsec-windows.exe /S
}

#Audio Drivers
function Install-AudioDriver {
    Write-Host "Installing audio driver"
    #Download Audio driver extracted from Razer Surround Sound
    Read-S3Object -BucketName demo-parsec -Key aws_audio.zip -File $path\aws_audio.zip
    Expand-Archive -Path $path\aws_audio.zip -DestinationPath $path -Force
    #Installing virtual sound device
    devcon64 install $path\aws_audio\rzsurroundvad.inf *rzsurroundvad
    #Initializing Audio Service
    Set-Service -Name audiosrv -StartupType Automatic
}

###Launcher Installs###
function Install-BattlenetLauncher {
    Write-Host "Installing Battle.net Launcher"
    (New-Object System.Net.WebClient).DownloadFile("https://www.battle.net/download/getInstallerForGame?os=win&locale=enUS&version=LIVE&gameProgram=BATTLENET_APP", "$path\Battle-net.exe") | Unblock-File
    Start-Process "$path\Battle-net.exe" -ArgumentList "--installpath=C:/Battle.net --locale=enUS"
}

function Install-OriginLauncher {
    Write-Host "Installing Origin Launcher"
    cinst origin
}

function Install-EpicGamesLauncher {
    Write-Host "Installing Epic Games Launcher"
    cinst epicgameslauncher
}

function Install-Golden {

    Write-Host -foregroundcolor red "
    THIS IS GALAXY.
    We are installing all the needed essentials to make this machine stream games
    "
    
    ##Create Temp Folder
    $path = New-TemporaryDirectory
    
    #Tooling
    Install-SSM
    Install-Chocolatey
    
    #Essentials
    Install-Base
    
    #Registry
    Disable-Updates
    Set-RegistryForceCloseApps
    Disable-NewNetworkWindow
    Disable-Logout
    Disable-Lock
    Set-Time
    Disable-ServerManager
    
    #Devices
    Disable-Devices
    Install-AudioDriver
    
    #Launchers
    Install-BattlenetLauncher
    Install-OriginLauncher
    Install-EpicGamesLauncher
    
    #Streaming Tech
    Install-Parsec
    
    #Clean Up
    Remove-TemporaryDirectory($path)
    
    Write-Host "Script ended. It's over. Stop looking at me." -ForegroundColor Green
    
    #TODO: Maybe it's already installed with new parsec installer? Test controller
    #Checks for Server 2019 and asks user to install Windows Xbox Accessories in order to let their controller work
    #USE THIS TO EXTRACT LATER: https://social.technet.microsoft.com/Forums/office/en-US/f5bd7dd6-36f4-4309-8dd5-7d746cb161d2/silent-install-of-xbox-360-controller-drivers?forum=w7itproinstall
    
}

#enable auto login
function Enable-WindowsAutoLogin { 
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/AutoLogon.zip", "$path\Autologon.zip") | Unblock-File
    Expand-Archive "$path\Autologon.zip" -DestinationPath "$path" -Force
    
    $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT -Uri http://169.254.169.254/latest/api/token
    $instanceId = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri http://169.254.169.254/latest/meta-data/instance-id
    Read-S3Object -BucketName demo-parsec -Key herpderp.pem -File $path\herpderp.pem
    $winPass = Get-EC2PasswordData -InstanceId $instanceId -PemFile $path\herpderp.pem
    $autoLoginP = Start-Process "$path\Autologon.exe" -ArgumentList "/accepteula", $autoLoginUser, $env:Computername, $winPass -PassThru -Wait
    If ($autoLoginP.ExitCode -eq 0) {
        Write-Host "Windows AutoLogin Enabled"
    } Else {
        Write-Error "Enable-WindowsAutoLogin FAILED"
    }
}

function __Get-MachineGUID {
    try {
        (Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\ -Name MachineGuid).MachineGUID
    }
    catch{
            Write-Warning "Failed to get Machine GUID from HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\"
    }
}

#let's get our parsec magical login file
function __Download-ParsecLoginFile {
    $parsecSessionId = '';

    $apiKey = "BkeFd7ROYH5rh5hmtnoXp2BFuPgG6Z7sa6G2JadX"
    $resource = "https://0pzg655b2l.execute-api.us-west-2.amazonaws.com/default/parsecLogin"

    $retries = 0
    while (($parsecSessionId -eq '') -and ($retries -lt 5)) {
        Start-Sleep -s (10*$retries) #anti-spam
        Write-Verbose "Getting Parsec Key - Retry: $retries"

        try{
            $headers =  @{ 
                "x-api-key" = $apiKey 
                "winguid" = __Get-MachineGUID
            }
            $parsecSessionId = Invoke-RestMethod -Method Get -Uri $resource -Headers $headers    
        } catch {
            Write-Verbose "Unable to get Parsec Key - Retry: $retries"
        }

        $retries++
    }

    if($parsecSessionId -eq '')
    {
        Write-Error "No Parsec Login File"
        return false;
    }
    else {
        Write-Host "Parsec Key recieved"
        return $parsecSessionId
    }
}

function Install-ParsecLoginFile {
    try {
        (__Download-ParsecLoginFile) | Out-File -FilePath "C:\Users\$autoLoginUser\AppData\Roaming\Parsec\user.bin" -Encoding ascii
        Write-Host "Parsec Login File Installed"
    }
    catch {
        Write-Error "Install-ParsecLoginFile FAILED"
    }
}

#TODO: Add uniq hostname IDs etc here..?
function Install-ParsecSettings {

    <#
    app_host=1
    app_run_level = 3
    encoder_h265 = 1
    encoder_min_bitrate = 100
    encoder_bitrate = 200
    server_resolution_x=3840
    server_resolution_x=2160
    server_refresh_rate=60
    #>
    
    #SERGEY SETTINGS - AKA 50mbps :)
    <# 
    app_host=1
    app_run_level = 3
    encoder_h265 = 1
    encoder_min_bitrate = 50
    encoder_bitrate = 50
    server_resolution_x=2560
    server_resolution_x=1440
    server_refresh_rate=60
    #>

    #SHERVIN SETTINGS AKA 25mbps
    <#
    app_host=1
    app_run_level = 3
    encoder_h265 = 1
    encoder_min_bitrate = 15
    encoder_bitrate = 25
    server_resolution_x=1920
    server_resolution_x=1080
    server_refresh_rate=60
    #>

    $parsecOptions = @"
app_host=1
app_run_level = 3
encoder_h265 = 1
encoder_min_bitrate = 15
encoder_bitrate = 25
server_resolution_x=1920
server_resolution_x=1080
server_refresh_rate=60
"@
    try{
        Write-Output $parsecOptions | Out-File -FilePath "C:\Users\Administrator\AppData\Roaming\Parsec\config.txt" -Encoding ascii
        Write-Host "Parsec Settings Installed"
    }
    catch {
        Write-Error "Install-ParsecSettings FAILED"
    }
}

function Install-Silver {
    Clear-Host

    Write-Host -foregroundcolor red "
    THIS IS GALAXY.
    We are installing all the needed essentials to make this machine stream games
    "
    
    ##Create Temp Folder
    $path = New-TemporaryDirectory
    
    Enable-WindowsAutoLogin
    Install-ParsecLoginFile
    Install-ParsecSettings
    
    #Clean Up
    Remove-TemporaryDirectory($path)
    
    #This is unfortunately required as autologin initializes only on reboot
    #In future there will be a separate autologin account and this won't be required
    Restart-Computer
}

function Show-Status {
    Write-Host "Awesome sauce"
}