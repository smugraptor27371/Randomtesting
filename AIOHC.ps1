function Show-MainMenu {
    Write-Host " ***************************"
    Write-Host " *         Main Menu       *" 
    Write-Host " ***************************" 
    Write-Host 
    Write-Host " 1.) HCSSD" 
    Write-Host " 2.) HCPFSSD"
    Write-Host " 3.) Additional tools" 
    Write-Host " 4.) Reset Win Updates 10/11" 
    Write-Host " 5.) Option 5"
    Write-Host " 6.) Option 6"
    Write-Host " 7.) Option 7"
    Write-Host " 8.) Option 8"
    Write-Host " 9.) Option 9"
    Write-Host "10.) Option 10"
    Write-Host "11.) Quit And Cleanup"
    Write-Host 
    Write-Host " Select an option and press Enter: "  -nonewline
}

function Execute-HCSSD {
    Write-Host "HCSSD selected updating all apps."
    new-item -path "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS" -itemtype directory           


$log = "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\transcript.txt"


Start-Transcript -Path "$log"

write-host "downloading whitelist"

Invoke-WebRequest -Uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/rkillwhitelist.txt -outfile "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\rkillwhitelist.txt"

Write-host "downloading Preperation"

$iwr = Invoke-WebRequest -Uri "https://www.bleepingcomputer.com/download/rkill/dl/10/"
$directlink = ($iwr.content | select-string -Pattern "url=.+rkill\.exe" -AllMatches).matches.value -replace "url=",""

Invoke-WebRequest -Uri $directlink -outfile "$env:TEMP\rkill.exe" 

Start-Process -FilePath "$env:TEMP\rkill.exe" -ArgumentList "-l", "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\Rkill.txt", "-w", "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\rkillwhitelist.txt" -Wait



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

# Perform a scan with Windows Defender
Write-Host "Performing a scan with Windows Defender..."
Start-MpScan -ScanType Quickscan -ScanPath $env:SystemDrive -Verbose



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
    Start-Process -FilePath $filePath1 -ArgumentList $arguments1 -redirectstandardoutput "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\KVRT.txt" -wait
 
    
    # Clean up the downloaded file after the execution
    Remove-Item $filePath1 -Force -erroraction silentlycontinue
}
else {
    Write-Host "Failed to download Kaspersky Virus Removal Tool."
}




# Define the URL and file path
$downloadUrl = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release"
$filePath = "$env:TEMP\adwcleaner.exe"

# Download ADWCleaner
Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath



# Check if the file was downloaded successfully
if (Test-Path $filePath) {
    # Run ADWCleaner with the specified arguments
    Start-Process -FilePath $filePath -ArgumentList "/eula", "/clean", "/noreboot"  -redirectstandardoutput  "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\ADW.txt" -wait
    # Clean up the downloaded file after the execution
    Remove-Item $filePath -Force -erroraction silentlycontinue
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

# Execute DISM because sometimes it needs to do it multiple times
Write-Host "Executing DISM..."
Start-Process -FilePath "C:\Windows\System32\Dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait

# Execute SFC again sometimes it needs multiple runs
Write-Host "Executing SFC..."
Start-Process -FilePath "C:\Windows\System32\sfc.exe" -ArgumentList "/scannow" -Wait

Write-host "downloading webroot"
invoke-webrequest -Uri "http://anywhere.webrootcloudav.com/zerol/syswranalyzer.exe" -outfile "$env:TEMP/Webroot.exe"
Write-Host "running"
start-process -filepath "$env:TEMP/webroot.exe"


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



Remove-Item C:\KVRT2020_Data -recurse -erroraction:silentlycontinue
New-Item -Path (Get-PSReadlineOption).HistorySavePath -Force

    Read-Host "Press Enter to continue..."
}

function Execute-HCPFSSD {
    Write-Host "HCPFSSD Selected only updating specific apps."
   new-item -path "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS" -itemtype directory           


$log = "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\transcript.txt"


Start-Transcript -Path "$log"


write-host "downloading whitelist"

Invoke-WebRequest -Uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/rkillwhitelist.txt -outfile "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\rkillwhitelist.txt"

Write-host "downloading Preperation"

$iwr = Invoke-WebRequest -Uri "https://www.bleepingcomputer.com/download/rkill/dl/10/"
$directlink = ($iwr.content | select-string -Pattern "url=.+rkill\.exe" -AllMatches).matches.value -replace "url=",""

Invoke-WebRequest -Uri $directlink -outfile "$env:TEMP\rkill.exe" 

Start-Process -FilePath "$env:TEMP\rkill.exe" -ArgumentList "-l", "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\Rkill.txt", "-w", "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\rkillwhitelist.txt" -Wait



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

# Perform a scan with Windows Defender
Write-Host "Performing a scan with Windows Defender..."
Start-MpScan -ScanType quickscan -ScanPath $env:SystemDrive -Verbose



Write-Host "Windows Defender scan completed."


#remove threats
remove-mpthreat



# Define the URL and file path
$downloadUrl1 = "https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe"
$filePath1 = "$env:TEMP\KVRT.exe"

# Download Kaspersky Virus Removal Tool
Invoke-WebRequest -Uri $downloadUrl1 -OutFile $filePath1

# Check if the file was downloaded successfully
if (Test-Path $filePath1) {
    # Define the command-line arguments
    $arguments1 = "-silent -accepteula -processlevel 3"
    
    # Run Kaspersky Virus Removal Tool with the specified arguments
    Start-Process -FilePath $filePath1 -ArgumentList $arguments1 -redirectstandardoutput "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\KVRT.txt" -Wait
    
    # Clean up the downloaded file after the execution
    Remove-Item $filePath1 -Force -erroraction silentlycontinue
}
else {
    Write-Host "Failed to download Kaspersky Virus Removal Tool."
}

# Define the URL and file path
$downloadUrl = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release"
$filePath = "$env:TEMP\adwcleaner.exe"

# Download ADWCleaner
Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath


# Check if the file was downloaded successfully
if (Test-Path $filePath) {
    # Run ADWCleaner with the specified arguments
    Start-Process -FilePath $filePath -ArgumentList "/eula", "/clean", "/noreboot" -RedirectStandardOutput "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS\ADW.txt" -Wait 
    # Clean up the downloaded file after the execution
    Remove-Item $filePath -Force -erroraction silentlycontinue
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


Write-host "downloading webroot"
invoke-webrequest -Uri "http://anywhere.webrootcloudav.com/zerol/syswranalyzer.exe" -outfile "$env:TEMP/Webroot.exe"
Write-Host "running"
start-process -filepath "$env:TEMP/webroot.exe"



winget update google.chrome --accept-source-agreements --accept-package-agreements
winget update mozilla.firefox --accept-source-agreements --accept-package-agreements
Winget update thedocumentfoundation.libreoffice --accept-source-agreements --accept-package-agreements
winget update Adobe.Acrobat.Reader.64-bit --accept-source-agreements --accept-package-agreements



Write-host "defrag/trim" 
defrag /C /O /V

stop-transcript




Remove-Item C:\KVRT2020_Data -recurse -erroraction:silentlycontinue

    Read-Host "Press Enter to continue..."
}

function Execute-AdditionalTools {
    Write-Host "Additional tools."
    $tempfolder = "C:\Healthchecktemp21z1"

$downloadurltool = "https://windows-repair-toolbox.com/download/click.php?id=Windows_Repair_Toolbox"

new-item -itemtype directory -path $tempfolder

write-host "downloading"

Invoke-WebRequest -uri $downloadurltool -outfile C:\Healthchecktemp21z1\HCAIO.zip

Write-Host "decompressing"

Expand-archive -path C:\Healthchecktemp21z1\HCAIO.zip -destinationpath $tempfolder
 
Write-Host "deleting zip"

remove-item -path C:\Healthchecktemp21z1\HCAIO.zip

ren C:\Healthchecktemp21z1\Windows_Repair_Toolbox.exe C:\Healthchecktemp21z1\HCAIO.exe

Remove-Item -path C:\Healthchecktemp21z1\custom\settings.xml

$xmlpath = 'C:\Healthchecktemp21z1\custom\settings.xml'

Invoke-WebRequest -uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/settings.xml -outfile $xmlpath

Write-Host "launching" 

C:\Healthchecktemp21z1\HCAIO.exe 


function Delete-Folder {
    param (
        [string]$userInput,
        [string]$folderPath
    )

   
    $processName = "AIOHC.exe"
    $isProcessRunning = Get-Process -Name $processName -ErrorAction SilentlyContinue

    if ($isProcessRunning) {
        Write-Output "Cannot delete folder. Close '$processName' program first."
        return $false  
    }

    if ($userInput -eq "123") {
        try {
            Remove-Item -Path $folderPath -Force -Recurse
            Write-Output "Deleted folder and its contents"
            return $true  
        } catch {
            Write-Output "Failed to delete folder and its contents: $_"
            return $false  
        }
    } else {
        Write-Output "Invalid input. Folder not deleted."
        return $false  
    }
}
$folderPath = "C:\Healthchecktemp21z1"  

while ($true) {
   
    $userInput = Read-Host "Type '123' and press Enter to delete the folder and its contents"
    
    $deleted = Delete-Folder -userInput $userInput -folderPath $folderPath

    if ($deleted) {
        break 
    }
}
    Read-Host "Press Enter to continue..."
}

function Execute-ResetUpdates {

    
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
    
    Write-Host "==============================================="
    Write-Host "-- Reset All Windows Update Settings to Stock -"
    Write-Host "==============================================="
      
        
  

    Read-Host "Press Enter to continue..."
}

function Execute-Option5 {
    Write-Host "Option 5 selected. Executing corresponding code."
    # tons of code here
    Read-Host "Press Enter to continue..."
}

function Execute-Option6 {
    Write-Host "Option 6 selected. Executing corresponding code."
    # tons of code here
    Read-Host "Press Enter to continue..."
}

function Execute-Option7 {
    Write-Host "Option 7 selected. Executing corresponding code."
    # tons of code here
    Read-Host "Press Enter to continue..."
}

function Execute-Option8 {
    Write-Host "Option 8 selected. Executing corresponding code."
    # tons of code here
    Read-Host "Press Enter to continue..."
}

function Execute-Option9 {
    Write-Host "Option 9 selected. Executing corresponding code."
    # tons of code here
    Read-Host "Press Enter to continue..."
}

function Execute-Option10 {
    Write-Host "Option 10 selected. Executing corresponding code."
    # tons of code here
    Read-Host "Press Enter to continue..."
}

cls

Do { 
    cls
    Show-MainMenu
    $Select = Read-Host "Select an option and press Enter: "
    Switch ($Select)
    {
        1 { Execute-HCSSD }
        2 { Execute-HCPFSSD }
        3 { Execute-AdditionalTools }
        4 { Execute-ResetUpdates }
        5 { Execute-Option5 }
        6 { Execute-Option6 }
        7 { Execute-Option7 }
        8 { Execute-Option8 }
        9 { Execute-Option9 }
        10 { Execute-Option10 }
    }
} While ($Select -ne 11)

write-host "deleting adw quarantine and logs"
remove-item -path "C:\AdwCleaner" -Recurse -force
Write-host "deleting health check logs"
Remove-item -path "$env:USERPROFILE\Desktop\HEALTHCHECKLOGS" -recurse -force
Write-host "removing %temp%"
Remove-Item -Path $env:TEMP\* -Force -Recurse -erroraction silentlycontinue



Write-host "wiping PShistory"
New-Item -Path (Get-PSReadlineOption).HistorySavePath -Force

