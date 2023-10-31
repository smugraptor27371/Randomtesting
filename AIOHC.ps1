$MainMenu = {
    Write-Host " ***************************"
    Write-Host " *         Main Menu       *" 
    Write-Host " ***************************" 
    Write-Host 
    Write-Host " 1.) HCSSD" 
    Write-Host " 2.) HCPFSSD"
    Write-Host " 3.) In development" 
    Write-Host " 4.) In development (reset win updates 10/11)" 
    Write-Host " 5.) Quit"
    Write-Host 
    Write-Host " Select an option and press Enter: "  -nonewline
}
cls

Do { 
    cls
    & $MainMenu
    $Select = Read-Host
    Switch ($Select)
    {
        1 {
            Write-Host "HCSSD selected may take a while."
            


Start-Transcript -Path "$env:USERPROFILE\Desktop\transcript.txt"

$computerSystem = Get-CimInstance CIM_ComputerSystem
$computerBIOS = Get-CimInstance CIM_BIOSElement
$computerOS = Get-CimInstance CIM_OperatingSystem
$computerCPU = Get-CimInstance CIM_Processor
$computerHDD = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = 'C:'"
Clear-Host

Write-Host "System Information for: " $computerSystem.Name -BackgroundColor DarkCyan
"Manufacturer: " + $computerSystem.Manufacturer
"Model: " + $computerSystem.Model
"Serial Number: " + $computerBIOS.SerialNumber
"CPU: " + $computerCPU.Name
"HDD Capacity: "  + "{0:N2}" -f ($computerHDD.Size/1GB) + "GB"
"HDD Space: " + "{0:P2}" -f ($computerHDD.FreeSpace/$computerHDD.Size) + " Free (" + "{0:N2}" -f ($computerHDD.FreeSpace/1GB) + "GB)"
"RAM: " + "{0:N2}" -f ($computerSystem.TotalPhysicalMemory/1GB) + "GB"
"Operating System: " + $computerOS.caption + ", Service Pack: " + $computerOS.ServicePackMajorVersion
"User logged In: " + $computerSystem.UserName
"Last Reboot: " + $computerOS.LastBootUpTime



Get-Disk | Get-StorageReliabilityCounter | Select-Object -Property "*"


# Update Windows Defender
Write-Host "Updating Windows Defender..."
Update-MpSignature -Verbose

# Wait for the update to finish
Write-Host "Waiting for Windows Defender update to complete..."
$UpdateInProgress = $true

while ($UpdateInProgress) {
    $UpdateInProgress = (Get-MpComputerStatus).EngineRefreshRequired
    Start-Sleep -Seconds 5
}

Write-Host "Windows Defender update completed."

# Perform a full scan with Windows Defender
Write-Host "Performing a full scan with Windows Defender..."
Start-MpScan -ScanType FullScan -ScanPath $env:SystemDrive -Verbose



Write-Host "Windows Defender scan completed."

#Remove threats
remove-mpthreat 


# Define the URL and file path
$downloadUrl1 = "https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe"
$filePath1 = "$env:TEMP\KVRT.exe"

# Download Kaspersky Virus Removal Tool
Invoke-WebRequest -Uri $downloadUrl1 -OutFile $filePath1

# Wait for the download to complete (adjust the sleep time as needed)
Start-Sleep -Seconds 10

# Check if the file was downloaded successfully
if (Test-Path $filePath1) {
    # Define the command-line arguments
    $arguments1 = "-silent -accepteula -processlevel 3"
    
    # Run Kaspersky Virus Removal Tool with the specified arguments
    Start-Process -FilePath $filePath1 -ArgumentList $arguments1 -Wait
    
    # Clean up the downloaded file after the execution
    Remove-Item $filePath1 -Force
}
else {
    Write-Host "Failed to download Kaspersky Virus Removal Tool."
}




# Define the URL and file path
$downloadUrl = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release"
$filePath = "$env:TEMP\adwcleaner.exe"

# Download ADWCleaner
Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath

# Wait for the download to complete (adjust the sleep time as needed)
Start-Sleep -Seconds 30

# Check if the file was downloaded successfully
if (Test-Path $filePath) {
    # Run ADWCleaner with the specified arguments
    Start-Process -FilePath $filePath -ArgumentList "/eula", "/clean", "/noreboot" -Wait
    # Clean up the downloaded file after the execution
    Remove-Item $filePath -Force
    Write-Host "adwclean done"
}
else {
    Write-Host "Failed to download ADWCleaner."
}

# Execute DISM
Write-Host "Executing DISM..."
Start-Process -FilePath "C:\Windows\System32\Dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait

# Execute SFC
Write-Host "Executing SFC..."
Start-Process -FilePath "C:\Windows\System32\sfc.exe" -ArgumentList "/scannow" -Wait

# Define a function to check if any updates are still in progress
function AreUpdatesInProgress {
    $output = winget upgrade --all --accept-source-agreements --accept-package-agreements --silent
    return $output.Contains("Running") -or $output.Contains("Pending")
}

# Run the initial upgrade command
winget upgrade --all --accept-source-agreements --accept-package-agreements

# Check for updates in a loop until there are no more updates in progress
while (AreUpdatesInProgress) {
    Write-Host "Waiting for updates to complete..."
    Start-Sleep -Seconds 10 # Adjust the sleep interval if needed
}

Write-Host "All apps have been updated."

Write-host "defrag/trim" 
defrag /C /O /V

stop-transcript

notepad "$env:USERPROFILE\Desktop\transcript.txt"



Remove-Item C:\KVRT2020_Data -recurse -erroraction:silentlycontinue
New-Item -Path (Get-PSReadlineOption).HistorySavePath -Force





            Read-Host "Press Enter to continue..."
        }
        2 {
            Write-Host "HCPFSSD Selected only updating specific apps."
            
 


Start-Transcript -Path "$env:USERPROFILE\Desktop\transcript.txt"

$computerSystem = Get-CimInstance CIM_ComputerSystem
$computerBIOS = Get-CimInstance CIM_BIOSElement
$computerOS = Get-CimInstance CIM_OperatingSystem
$computerCPU = Get-CimInstance CIM_Processor
$computerHDD = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = 'C:'"
Clear-Host

Write-Host "System Information for: " $computerSystem.Name -BackgroundColor DarkCyan
"Manufacturer: " + $computerSystem.Manufacturer
"Model: " + $computerSystem.Model
"Serial Number: " + $computerBIOS.SerialNumber
"CPU: " + $computerCPU.Name
"HDD Capacity: "  + "{0:N2}" -f ($computerHDD.Size/1GB) + "GB"
"HDD Space: " + "{0:P2}" -f ($computerHDD.FreeSpace/$computerHDD.Size) + " Free (" + "{0:N2}" -f ($computerHDD.FreeSpace/1GB) + "GB)"
"RAM: " + "{0:N2}" -f ($computerSystem.TotalPhysicalMemory/1GB) + "GB"
"Operating System: " + $computerOS.caption + ", Service Pack: " + $computerOS.ServicePackMajorVersion
"User logged In: " + $computerSystem.UserName
"Last Reboot: " + $computerOS.LastBootUpTime



Get-Disk | Get-StorageReliabilityCounter | Select-Object -Property "*"







# Update Windows Defender
Write-Host "Updating Windows Defender..."
Update-MpSignature -Verbose

# Wait for the update to finish
Write-Host "Waiting for Windows Defender update to complete..."
$UpdateInProgress = $true

while ($UpdateInProgress) {
    $UpdateInProgress = (Get-MpComputerStatus).EngineRefreshRequired
    Start-Sleep -Seconds 5
}

Write-Host "Windows Defender update completed."

# Perform a full scan with Windows Defender
Write-Host "Performing a full scan with Windows Defender..."
Start-MpScan -ScanType FullScan -ScanPath $env:SystemDrive -Verbose



Write-Host "Windows Defender scan completed."


#remove threats
remove-mpthreat



# Define the URL and file path
$downloadUrl1 = "https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe"
$filePath1 = "$env:TEMP\KVRT.exe"

# Download Kaspersky Virus Removal Tool
Invoke-WebRequest -Uri $downloadUrl1 -OutFile $filePath1

# Wait for the download to complete (adjust the sleep time as needed)
Start-Sleep -Seconds 10

# Check if the file was downloaded successfully
if (Test-Path $filePath1) {
    # Define the command-line arguments
    $arguments1 = "-silent -accepteula -processlevel 3"
    
    # Run Kaspersky Virus Removal Tool with the specified arguments
    Start-Process -FilePath $filePath1 -ArgumentList $arguments1 -Wait
    
    # Clean up the downloaded file after the execution
    Remove-Item $filePath1 -Force
}
else {
    Write-Host "Failed to download Kaspersky Virus Removal Tool."
}




# Define the URL and file path
$downloadUrl = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release"
$filePath = "$env:TEMP\adwcleaner.exe"

# Download ADWCleaner
Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath

# Wait for the download to complete (adjust the sleep time as needed)
Start-Sleep -Seconds 30

# Check if the file was downloaded successfully
if (Test-Path $filePath) {
    # Run ADWCleaner with the specified arguments
    Start-Process -FilePath $filePath -ArgumentList "/eula", "/clean", "/noreboot" -Wait
    # Clean up the downloaded file after the execution
    Remove-Item $filePath -Force
    Write-Host "adwclean done"
}
else {
    Write-Host "Failed to download ADWCleaner."
}

# Execute DISM
Write-Host "Executing DISM..."
Start-Process -FilePath "C:\Windows\System32\Dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait

# Execute SFC
Write-Host "Executing SFC..."
Start-Process -FilePath "C:\Windows\System32\sfc.exe" -ArgumentList "/scannow" -Wait


winget update google.chrome --accept-source-agreements --accept-package-agreements
winget update mozilla.firefox --accept-source-agreements --accept-package-agreements
Winget update thedocumentfoundation.libreoffice --accept-source-agreements --accept-package-agreements
winget update Adobe.Acrobat.Reader.64-bit --accept-source-agreements --accept-package-agreements



Write-host "defrag/trim" 
defrag /C /O /V

stop-transcript

notepad "$env:USERPROFILE\Desktop\transcript.txt"


Remove-Item C:\KVRT2020_Data -recurse -erroraction:silentlycontinue
New-Item -Path (Get-PSReadlineOption).HistorySavePath -Force





            Read-Host "Press Enter to continue..."
        }
        3 {
            Write-Host "Option 3 selected. Executing corresponding code."
            # Code for option 3 goes here
            Read-Host "Press Enter to continue..."
        }
        4 {
            Write-Host "Option 4 selected. Executing corresponding code."
            Write-Host "1. Stopping Windows Update Services..."
    Stop-Service -Name BITS
    Stop-Service -Name wuauserv
    Stop-Service -Name appidsvc
    Stop-Service -Name cryptsvc
Write-Host "2. Remove QMGR Data file..."
    Remove-Item "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue

Write-Host "3. Renaming the Software Distribution and CatRoot Folder..."
    Rename-Item $env:systemroot\SoftwareDistribution SoftwareDistribution.bak -ErrorAction SilentlyContinue
    Rename-Item $env:systemroot\System32\Catroot2 catroot2.bak -ErrorAction SilentlyContinue

Write-Host "4. Removing old Windows Update log..."
    Remove-Item $env:systemroot\WindowsUpdate.log -ErrorAction SilentlyContinue

Write-Host "5. Resetting the Windows Update Services to default settings..."
    Start-Process -NoNewWindow -FilePath "sc.exe" -ArgumentList "sdset", "bits", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
    Start-Process -NoNewWindow -FilePath "sc.exe" -ArgumentList "sdset", "wuauserv", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
    Set-Location $env:systemroot\system32

Write-Host "6. Registering some DLLs..."
$DLLs = @(
    "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
    "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
    "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
    "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
    "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
    "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
    "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
)
foreach ($dll in $DLLs) {
    Start-Process -NoNewWindow -FilePath "regsvr32.exe" -ArgumentList "/s", $dll
}

Write-Host "7) Removing WSUS client settings..."
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate") {
    Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "AccountDomainSid", "/f"
    Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "PingID", "/f"
    Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "SusClientId", "/f"
}

Write-Host "8) Resetting the WinSock..."
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winsock", "reset"
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winhttp", "reset", "proxy"
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "int", "ip", "reset"

Write-Host "9) Delete all BITS jobs..."
    Get-BitsTransfer | Remove-BitsTransfer

Write-Host "10) Attempting to install the Windows Update Agent..."
If ([System.Environment]::Is64BitOperatingSystem) {
    Start-Process -NoNewWindow -FilePath "wusa" -ArgumentList "Windows8-RT-KB2937636-x64", "/quiet"
}
else {
    Start-Process -NoNewWindow -FilePath "wusa" -ArgumentList "Windows8-RT-KB2937636-x86", "/quiet"
}

Write-Host "11) Starting Windows Update Services..."
    Start-Service -Name BITS
    Start-Service -Name wuauserv
    Start-Service -Name appidsvc
    Start-Service -Name cryptsvc

Write-Host "12) Forcing discovery..."
    Start-Process -NoNewWindow -FilePath "wuauclt" -ArgumentList "/resetauthorization", "/detectnow"

    ipconfig /flushdns

    Write-Host "Process complete. Please reboot your computer."

    $ButtonType = [System.Windows.MessageBoxButton]::OK
    $MessageboxTitle = "Reset Windows Update "
    $Messageboxbody = ("Stock settings loaded.`n Please reboot your computer")
    
    Write-Host "==============================================="
    Write-Host "-- Reset All Windows Update Settings to Stock -"
    Write-Host "==============================================="
            Read-Host "Press Enter to continue..."
        }
    }
} While ($Select -ne 5)
