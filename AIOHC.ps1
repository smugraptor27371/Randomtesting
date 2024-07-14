#Requires -runasadministrator


function prep {
$disk = Get-PSDrive C | Select-Object -ExpandProperty Free
$free_space_gb = $disk / 1GB
if ($free_space_gb -lt 5) {
    Write-Host "Less than 5GB of free disk space available."
    stop-transcript
    break
} else {
    Write-Host "There is sufficient disk space available."  
}
}

function folders_prep{
if (Test-Path -Path "C:\HCLOGS314") { 
    Remove-Item -Path "C:\HCLOGS314" -Recurse -Force
}
New-Item -Path "C:\HCLOGS314" -ItemType Directory
new-item -path "C:\HCLOGS314\regback" -itemtype directory
new-item -path "C:\HCLOGS314\full_logs" -itemtype directory
new-item -path "C:\HCLOGS314\image_repair_logs" -itemtype directory
new-item -path "C:\HCLOGS314\overview.txt"
if (Test-Path -Path 'C:\AdwCleaner') {
Get-ChildItem 'C:\AdwCleaner\Logs\*.txt' | remove-item -force 
}
Get-ChildItem $env:temp | remove-item -recurse -ErrorAction SilentlyContinue
}

function Handle-tempDupes {
$itemsToDelete = @(
    "diskhealth.zip",
    "diskgealth",
    "hwmon.zip",
    "hwmon",
    "rkil.exe",
    "kvrt.exe",
    "adwcleaner.exe",
    "webroot.exe",
    "wiztree.zip",
    "wiztreeunzipped"
)
$tempPath = $env:TEMP
foreach ($item in $itemsToDelete) {
    $fullPath = Join-Path -Path $tempPath -ChildPath $item
    if (Test-Path -Path $fullPath -PathType Leaf) {
        try {
            Remove-Item -Path $fullPath -Force
            Write-Output "Deleted file: $fullPath"
        } catch {
            Write-Output "Failed to delete file: $fullPath. Error: $_"
        }
    }
    elseif (Test-Path -Path $fullPath -PathType Container) {
        try {
            Remove-Item -Path $fullPath -Recurse -Force
            Write-Output "Deleted folder: $fullPath"
        } catch {
            Write-Output "Failed to delete folder: $fullPath. Error: $_"
        }
    }
    else {
        Write-Output "Item not found: $fullPath"
    }
}
}

function regbackup {
try {
    Write-host "Backing up registry"
    reg export HKEY_classes_root C:\HCLOGS314\regback\classesroot.reg
    reg export HKEY_current_user C:\HCLOGS314\regback\currentuser.reg
    reg export HKEY_Local_machine C:\HCLOGS314\regback\localmachine.reg
    reg export HKEY_users C:\HCLOGS314\regback\users.reg
    reg export HKEY_current_config C:\HCLOGS314\regback\currentconfig.reg
    Write-Host "Registry backup successful"
} catch {
    Write-Host "Registry backup unsuccessful"
}
}

function disk_health_check {
write-host "Downloading disk health Checker"
invoke-webrequest -uri https://www.harddisksentinel.com/hdsentinel_pro_portable.zip -outfile "$env:TEMP\diskhealth.zip"
Expand-Archive -path "$env:TEMP\diskhealth.zip" -destinationpath "$Env:TEMP\diskhealth"
Start-Process -FilePath "$env:TEMP\diskhealth\HDSentinel.exe"
}

function hwmonitor {
write-host "Downloading HWmonitor"
invoke-webrequest -uri https://download.cpuid.com/hwmonitor/hwmonitor_1.52.zip -outfile "$env:TEMP\hwmon.zip"
Expand-Archive -path "$env:TEMP\hwmon.zip" -destinationpath "$Env:TEMP\hwmon"
Start-Process -FilePath "$env:TEMP\hwmon\HWMonitor_x64.exe"
}

Function R_kill {
write-host "downloading whitelist"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/rkillwhitelist.txt -outfile "C:\HCLOGS314\rkillwhitelist.txt"
$tempPath = "$env:TEMP"
Add-content -path "C:\HCLOGS314\Rkillwhitelist.txt" -value "$tempPath\hwmon\HWMonitor_x64.exe"
Add-content -path "C:\HCLOGS314\Rkillwhitelist.txt" -value "$tempPath\diskhealth\HDSentinel.exe"
Write-host "downloading Preperation"
$iwr = Invoke-WebRequest -Uri "https://www.bleepingcomputer.com/download/rkill/dl/10/"
$directlink = ($iwr.content | select-string -Pattern "url=.+rkill\.exe" -AllMatches).matches.value -replace "url=",""
Invoke-WebRequest -Uri $directlink -outfile "$env:TEMP\rkill.exe" 
Start-Process powershell -ArgumentList "-NoExit", "-Command", "while (`$true) { Start-Sleep -Seconds 60; `$fileSize = (Get-Item 'C:\HCLOGS314\full_logs\Rkill.txt').Length; if (`$fileSize -ge 500) { Stop-Process -Name rkill -Force; Stop-Process -Name rkill64 -Force; start-sleep 10; exit; } else { Write-Host 'Waiting 1 min'; } }"
Start-Process -FilePath "$env:TEMP\rkill.exe" -ArgumentList "-l", "C:\HCLOGS314\full_logs\Rkill.txt", "-w", "C:\HCLOGS314\rkillwhitelist.txt" 
}

function chkdsk/scan {
Write-host "running chkdsk /scan"
chkdsk /scan /perf >> C:\HCLOGS314\full_logs\chkdsk.txt
}

function get_pcinfo {
$cpuInfo = Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Name
"CPU = $cpuInfo" | Out-File -FilePath "C:\HCLOGS314\overview.txt"
$ramInfo = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory
$ramInGB = [math]::Round($ramInfo / 1GB, 2)
"RAM = $ramInGB GB" | Out-File -FilePath "C:\HCLOGS314\overview.txt"
}

function Check-WindowsDefenderStatus {
    $Global:defenderenabled = $null
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $registryKey = "DisableAntiSpyware"
    if (Test-Path "$registryPath\$registryKey") {
        $disableAntiSpyware = Get-ItemProperty -Path $registryPath -Name $registryKey       
        if ($disableAntiSpyware.$registryKey -eq 1) {
            Write-Output "Windows Defender is disabled."
            $Global:defenderenabled = "false"
        } else {
            Write-Output "Windows Defender is enabled."
            $Global:defenderenabled = "true"
        }
    } else {
        Write-Output "Windows Defender is enabled."
        $Global:defenderenabled = "true"
    }
}




function DefenderScanType {
$no = @("Q", "q")
$yes = @("F", "f")
do
{
    $answ = read-host "Defender scan type? (Q/F)"
}
until($no -contains $answ -or $yes -contains $answ)

if($no -contains $answ) #quick
{
 $Global:Defenderscantype = "Quickscan"   
}
elseif($yes -contains $answ) #full
{
 $Global:Defenderscantype = "Fullscan"  
}
}




Function update_and_run_windows_defender {
$overviewpath = "C:\HCLOGS314\overview.txt"
$defenderdisabledoutput = "Registry indicates windows defender is disabled. This is usually because of third party antivirus. Skipping scan to prevent error message"
$defenderenabledoutput =  "Registry indicates windows defender is enabled. Scan was attempted"
$defenderinvalidvalue = "Value found in disableantispyware was not 0 or 1. Investigate manually"
if ($global:defenderenabled -eq "true"){
Update-MpSignature -Verbose
Start-MpScan -ScanType $Global:Defenderscantype -ScanPath $env:SystemDrive -Verbose
remove-mpthreat -verbose
add-content -path $overviewpath -value $defenderenabledoutput
}elseif ($global:defenderenabled -eq "false"){
Write-host "skipping defender scan due to 3rd party antivirus"
add-content -path $overviewpath -value $defenderdisabledoutput
}else{
Write-host "you should not see this. It indicates that the registry key disableantispyware retuned a value other than 0 or 1."
add-content -path $overviewpath -value $defenderinvalidvalue
}
}

function KVRT {
Write-host "kvrt downloading and running"
$downloadUrl1 = "https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe"
$filePath1 = "$env:TEMP\KVRT.exe"
Invoke-WebRequest -Uri $downloadUrl1 -OutFile $filePath1
if (Test-Path $filePath1) {
    $arguments1 = "-silent -accepteula -processlevel 1"
    Start-Process -FilePath $filePath1 -ArgumentList $arguments1 -redirectstandardoutput "C:\HCLOGS314\full_logs\KVRT.txt" -Wait
    Remove-Item $filePath1 -Force -erroraction silentlycontinue
}
else {
    Write-Host "Failed to download Kaspersky Virus Removal Tool."
}
}

function ADW_malwarebytes {
Write-host "ADW downloading and running"
$downloadUrl = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release"
$filePath = "$env:TEMP\adwcleaner.exe"
Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath
if (Test-Path $filePath) {
    Start-Process -FilePath $filePath -ArgumentList "/eula", "/scan"  -Wait 
    Remove-Item $filePath -Force -erroraction silentlycontinue
    start-sleep 2
    Write-Host "adwclean done"
    Get-ChildItem 'C:\AdwCleaner\Logs\*.txt' | Rename-Item -NewName "ADW.txt"
    copy-Item -path 'C:\AdwCleaner\Logs\ADW.txt' -destination 'C:\HCLOGS314\full_logs\ADW.txt' -force
}
else {
    Write-Host "Failed to download ADWCleaner."
}
}

function runsfc{
$logpath = "C:\HCLOGS314\image_repair_logs"
sfc /scannow >> "$logpath\sfc.txt"
    start-sleep 5
    $fileContent = Get-Content -Path "$logpath/sfc.txt" -Raw
    $contentWithoutSpaces = $fileContent -replace '[^\w\s]|(?<=\w)\s+(?=\w)',''
    $contentWithoutSpaces | Set-Content -Path "$logpath/sfc.txt"
$sfcnoviolations = "Windows Resource Protection did not find any integrity violations" 
$sfcmaderepairs = "Windows Resource Protection found corrupt files and successfully repaired them"
$sfcnorepairs = "Windows Resource Protection found corrupt files but was unable to fix some of them"
$sfcrepairservice = "Windows Resource Protection could not start the repair service"
$noviolationstext = "SFC = No Integrity Violations"
$maderepairstext = "SFC = Successfully repaired system files"
$norepairstext = "SFC = Unable to repair some system files"
$repairservicetext = "SFC = Could not start repair service"
$overviewpath = "C:\HCLOGS314\overview.txt"
$sfcresult = get-content -path "$logpath\sfc.txt" -tail 20
if ($sfcresult -eq $sfcnoviolations){
Add-content -path $overviewpath -value $noviolationstext
}elseif ($sfcresult -eq $sfcmaderepairs){
Add-content -path $overviewpath -value $maderepairstext
}elseif ($sfcresult -eq $sfcnorepairs){
Add-content -path $overviewpath -value $norepairstext
}elseif ($sfcresult -eq $sfcrepairservice){
Add-content -path $overviewpath -value $repairservicetext
}else{
add-content -path $overviewpath -value "error check full sfc log" 
}
}

function rundism{
$logpath = "C:\HCLOGS314\image_repair_logs"
dism /online /cleanup-image /restorehealth >> $logpath\dism.txt
}

Function update_common_apps {
if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
    add-content -path "C:\HCLOGS314\overview.txt" -value "Updates = failed, most likely winget not working"
}
else {
$updatelogpath = "C:\HCLOGS314\full_logs"
$prognotinstalled = "No installed package found matching input criteria."
$overviewpath = "C:\HCLOGS314\overview.txt"
$updatesuccess = "Successfully installed"
$latestinstalled = "No newer package versions are available from the configured sources."
$librenotinstalled = "Libre Office update = Program not installed"
$libreofficesuccesstext = "Libre Office update = Successfully updated"
$libreofficelatest = "Libre Office update = Newest version installed already"
$readernotinstalled = "Adobe Reader update = Program not installed"
$readersuccesstext = "Adobe reader update = Successfully updated"
$lreaderlatest = "Adobe Reader update = Newest version installed already"
Winget update thedocumentfoundation.libreoffice --accept-source-agreements --accept-package-agreements --silent >> "$updatelogpath\libre.txt"
$libreresult = get-content -path "$updatelogpath\libre.txt" -tail 2
if ($libreresult -eq $prognotinstalled) {
add-content -path $overviewpath -value $librenotinstalled 
}elseif ($libreresult -eq $updatesuccess) {
add-content -path $overviewpath -value $libreofficesuccesstext  
}elseif ($libreresult -eq $latestinstalled){
add-content -path $overviewpath -value $libreofficelatest
}else{
add-content -path $overviewpath -value "Libre Office update = unknown string found; zip and send logs to support development"
}
Winget update Adobe.Acrobat.Reader.64-bit --accept-source-agreements --accept-package-agreements --silent >> "$updatelogpath\reader.txt"
$readerresult = get-content -path "$updatelogpath\Reader.txt" -tail 2
if ($readerresult -eq $prognotinstalled) {
add-content -path $overviewpath -value $readernotinstalled 
}elseif ($readerresult -eq $updatesuccess) {
add-content -path $overviewpath -value $readersuccesstext  
}elseif ($readerresult -eq $latestinstalled){
add-content -path $overviewpath -value $readerlatest
}else{
add-content -path $overviewpath -value "Adobe reader update = unknown string found; zip and send logs to support development"
}
}
}

function launch_human_apps {
devmgmt
cleanmgr
}

function disable_Some_things {
disable-windowserrorreporting
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
}

function defrag/trim{
defrag /C /O /V
}

function webroot{
invoke-webrequest -Uri "http://anywhere.webrootcloudav.com/zerol/syswranalyzer.exe" -outfile "$env:TEMP/Webroot.exe"
start-process -filepath "$env:TEMP/webroot.exe"
}

function wiztree{
$wiztreeurl = "https://www.diskanalyzer.com/files/wiztree_4_16_portable.zip"
$wiztreeloc = "$env:TEMP\wiztree.zip"  
Invoke-WebRequest -Uri $wiztreeurl -outfile $wiztreeloc
Expand-archive -path $wiztreeloc -destinationpath $env:TEMP\wiztreeunzipped
Start-Process -FilePath $env:TEMP\wiztreeunzipped\Wiztree64.exe
}

function hmpro{
invoke-webrequest -uri "https://files.surfright.nl/HitmanPro_x64.exe" -outfile "$env:temp/Hitmanpro64.exe"
start-process -filepath "$env:TEMP/Hitmanpro64.exe"
}

function memdump{
Invoke-WebRequest -uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/memdump.reg -outfile $env:temp/memdump.reg
reg import $env:temp\memdump.reg 
}

function create_overview{
if (Test-Path -Path "C:\HCLOGS314\full_logs\Rkill.txt" ) {
    notepad C:\HCLOGS314\full_logs\rkill.txt
} else { 
    add-content -path "C:\HCLOGS314\overview.txt" -value Rkill = Log not found check full logs
}
if (Test-Path -Path "C:\HCLOGS314\full_logs\chkdsk.txt" ) {
                if (Get-Content -Path "C:\HCLOGS314\full_logs\chkdsk.txt" | Select-String -Pattern "found no problems") {
                 add-content -path "C:\HCLOGS314\overview.txt" -value "Disk corruption = false"
                 } else {
                 add-content -path "C:\HCLOGS314\overview.txt" -value "Disk corruption = true"
                }
} else {
    add-content -path "C:\HCLOGS314\overview.txt" -value "Disk corruption = Log not found check full logs"
}
if (Test-Path -Path "C:\HCLOGS314\full_logs\kvrt.txt" ) {   
    if (Get-Content "C:\HCLOGS314\full_logs\kvrt.txt" | Select-String -Pattern "Detected: ([1-9]\d*)") {
   add-content -path "C:\HCLOGS314\overview.txt" -value "KVRT = Issues found check log"
    }else{
    add-content -path "C:\HCLOGS314\overview.txt" -value "KVRT = No Issues found "
    }
} else {
    add-content -path "C:\HCLOGS314\overview.txt" -value "KVRT = Log not found check full log"
}

if (Test-Path -Path "C:\HCLOGS314\full_logs\adw.txt" ) {

   if (Get-Content "C:\HCLOGS314\full_logs\adw.txt" | Select-String -Pattern "Total threat items found: ([1-9]\d*)") {
   add-content -path "C:\HCLOGS314\overview.txt" -value "ADW = Found items check logs and clean if needed"
   }else{
   add-content -path "C:\HCLOGS314\overview.txt" -value "ADW = Found no items"
   }
} else {
    add-content -path "C:\HCLOGS314\overview.txt" -value "ADW = Log not found check full logs"
}
if ($global:wasoverridden -eq "true"){
   add-content -path "C:\HCLOGS314\overview.txt" -value "Pending reboot = $global:pendingreason"
   add-content -path "C:\HCLOGS314\overview.txt" -value "Was reboot detection overridden = $global:wasoverridden"
}elseif($global:wasoverridden -eq "false"){
   add-content -path "C:\HCLOGS314\overview.txt" -value "Pending reboot = $global:pendingreason"
   add-content -path "C:\HCLOGS314\overview.txt" -value "Was reboot detection overridden = $global:wasoverridden"
}else{
   add-content -path "C:\HCLOGS314\overview.txt" -value "Pending reboot = script error"
   add-content -path "C:\HCLOGS314\overview.txt" -value "Was reboot detection overridden = script error"
}
$uptime = (Get-Counter '\System\System Up Time').CounterSamples[0].CookedValue
$uptime_timespan = [TimeSpan]::FromSeconds($uptime)
Write-Host "Uptime: $($uptime_timespan.Days) days, $($uptime_timespan.Hours) hours, $($uptime_timespan.Minutes) minutes, $($uptime_timespan.Seconds) seconds"
if ($uptime_timespan.Days -ge 100){
add-content -path "C:\HCLOGS314\overview.txt" -value "System uptime is greater than 100 days - Thats wild"
}elseif($uptime_timespan.Days -ge 3){
add-content -path "C:\HCLOGS314\overview.txt" -value "System uptime is greater than 3 days - This is not an issue by itself but could explain weird issues"
}elseif($uptime_timespan.Days -lt 2){
add-content -path "C:\HCLOGS314\overview.txt" -value "System uptime is less than 2 days - This is good"
}

#Secureboot detection
$secureboot = Confirm-SecureBootUEFI
$securebootdisabled = "Secureboot = Supported but Not Enabled"
$securebootenabled = "Secureboot = Supported and enabled"
$securebootNotsupported ="Secureboot = Not Supported and not active"
$securebootissues = "Secureboot = ERROR : secureboot unable to detect properly (confirm-securebootuefi returned invalid data)"
$securebootlog = $null
if($secureboot -eq $false){
$securebootlog = $securebootdisabled 
}elseif($secureboot -eq $true){
$securebootlog = $securebootenabled
}elseif($secureboot -eq "Cmdlet not supported on this platform"){
$securebootlog = $securebootNotsupported
}else{
$securebootlog = $securebootissues
}
Add-content -path "C:\HCLOGS314\overview.txt" -value "$securebootlog"
#End of secureboot detection

}

function cleanup{
 $processes = Get-Process | Where-Object { $_.Name -ilike "*hdsentinel*" }
    if ($processes) {
        Write-Host "HDSentinel is running. Stopping the process..."
        $processes | ForEach-Object { Stop-Process -Id $_.Id -Force }
        Write-Host "HDSentinel process has been stopped."
    } else {
        Write-Host "HDSentinel is not running."
    }
Remove-Item -path "C:\AdwCleaner" -recurse -force
Remove-item -path "C:\HCLOGS314" -recurse -force
Remove-item -path "$env:TEMP\*" -recurse -force -erroraction SilentlyContinue
New-item -path (get-psreadlineoption).historysavepath -force
}

#aditional tools function
function aditionaltools {
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
}

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

$folderPath = "C:\Healthchecktemp21z1"  
while ($true) {   
    $userInput = Read-Host "Type '123' and press Enter to delete the folder and its contents"
    $deleted = Delete-Folder -userInput $userInput -folderPath $folderPath
    if ($deleted) {
        break 
    }
}
}

#nukedesk
function nukedesk {
 while ($true) {
    Write-Host "Select an option:"
    Write-Host "1. NukeDesk"
    Write-Host "2. Restore Hostfile"
    Write-Host "3. Exit and delete backup"  
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        1 {
            Write-Host "Modifying host file"
            $domainsToBlock = @("anydesk.com", "net.anydesk.com", "www.anydesk.com", "https://anydesk.com/en-gb", "https://anydesk.com","https://fastsupport.gotoassist.com")
            $blockIPAddress = "127.0.0.1"
            $hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
            $backupFilePath = "$env:SystemRoot\System32\drivers\etc\hosts.bak"
            if (-not (Test-Path -Path $hostsFilePath)) {
                Write-Host "Hosts file not found."
                Exit
            }
            Copy-Item -Path $hostsFilePath -Destination $backupFilePath -Force
            foreach ($domainToBlock in $domainsToBlock) {
                if (-not (Get-Content $hostsFilePath | Select-String -Pattern $domainToBlock)) {
                    Add-Content -Path $hostsFilePath -Value "$blockIPAddress`t$domainToBlock"
                    Add-Content -Path $hostsFilePath -Value "$blockIPAddress`t*.$domainToBlock"
                    Write-Host "Blocked $domainToBlock and its subdomains."
                } else {
                    Write-Host "$domainToBlock is already blocked."
                }
            }
            ipconfig /flushdns
            break
        }
        2 {
            Write-Host "Reverting host file"
            $hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
            $backupFilePath = "$env:SystemRoot\System32\drivers\etc\hosts.bak"
            if (-not (Test-Path -Path $backupFilePath)) {
                Write-Host "Backup file not found. Nothing to restore."
                break
            }
            Copy-Item -Path $backupFilePath -Destination $hostsFilePath -Force
            Write-Host "Restored the original hosts file from the backup."
            ipconfig /flushdns
            break
        }
        3 {
            Write-Host "Exit and delete backup"
            Remove-Item "$env:SystemRoot\System32\drivers\etc\hosts.bak" -ErrorAction SilentlyContinue
            ipconfig /flushdns
            return
        }
        default {
            Write-Host "Invalid choice. Please enter 1, 2, or 3."
        }
    }
}
}

#registry changes
function regexport {
 Write-host "backing up registry keys"
$logpathtocheck = "C:\HCLOGS314"
if (Test-Path $logpathtocheck) {
    Write-Host "Folder already exists"
} else {
    Write-Host "Folder does not exist, creating folder"
    New-Item -itemtype Directory -path "C:\HCLOGS314"
} 
reg export HKEY_classes_root "C:\HCLOGS314\classes_root"
reg export HKEY_current_user "C:\HCLOGS314\current_user"
reg export HKEY_Local_machine "C:\HCLOGS314\localmachine.reg"
reg export HKEY_users "C:\HCLOGS314\\users.reg"
reg export HKEY_current_config "C:\HCLOGS314\currentconfig.reg"
}

function regchanges {
 while ($true) {
    Write-Host "Select an option:"
    Write-Host "1. All reg changes"
    Write-Host "2. Telemetry changes"
    Write-Host "3. Search suggestions and cortana changes"
    Write-Host "4. Work in progress"
    Write-Host "5. Exit"
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        1 {
            Write-Host "All (telemetry, tips and searchbox)"
regexport
Write-host "downloading reg files"
Invoke-WebRequest -uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/telemetry.reg -destinationpath $env:temp/telemetry.reg
Write-host "applying keys..."
reg import $env:temp\telemtry.reg
Write-host "downloading reg files"
Invoke-WebRequest -uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/suggestions_cortana_ect.reg -destinationpath $env:temp/search.reg
Write-host "applying keys..."
reg import $env:temp\search.reg
            break
        }
        2 {
            Write-Host "Telemetry"
regexport
Invoke-WebRequest -uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/telemetry.reg -destinationpath $env:temp/telemetry.reg
Write-host "applying keys..."
reg import $env:temp\telemtry.reg
            break
        }
        3 {
            Write-Host "Suggestions_cortanaect.reg "
regexport
Write-host "downloading reg files"
Invoke-WebRequest -uri https://raw.githubusercontent.com/smugraptor27371/Randomtesting/main/suggestions_cortana_ect.reg -destinationpath $env:temp/search.reg
Write-host "applying keys..."
reg import $env:temp\search.reg
            break
        }
        4 {
            Write-Host " work in progress"
            break
        }
        5 {
            Write-Host "Exit"
            return
        }
        default {
            Write-Host "Invalid choice. Please enter 1-5"
        }
    }
}
    Read-Host "Press Enter to continue..."
}

function Check-PendingReboot {
    $global:pendingreason = "None"
    $global:wasoverridden = "false"
    $rebootPending = $false
    $wuKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
    if (Test-Path "$wuKeyPath\RebootRequired") {
        set-variable -name "$global:pendingreason" -value "Updates"
        $rebootPending = $true
    }
    $cbsKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
    if (Test-Path "$cbsKeyPath\RebootPending") {
        $global:pendingreason = "Component"
        $rebootPending = $true
    }
    $renameKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $renameValue = Get-ItemProperty -Path $renameKeyPath -Name FileRenameOperations -ErrorAction SilentlyContinue
    if ($renameValue -ne $null -and $renameValue.FileRenameOperations.Length -gt 0) {
        $global:pendingreason = "File" 
        $rebootPending = $true
    }
    if ($rebootPending) {
        Override-check
    } else {
        Write-host "No reboot is pending, continuing."
    }
}

function override-check {
 if ($global:pendingreason -match "updates"){
 write-host "The Registry indicates a windows update waiting for a restart; do not override this unless you are sure it is misreporting"
 override-pendingreboot
 }elseif ($global:pendingreason -match "file" ){
 Write-host "The Registry indicates an offline file rename or deletion; this is almost always safe to override"
 override-pendingreboot
 }elseif ($global:pendingreason -match "component"){
 Write-host "The Registry indicates a pending CBS operation; do not override unless you are sure it is misreporting"
 override-pendingreboot
 }elseif ($global:pendingreason -match "placeholder"){
 write-host "Looks like the Pending Reboot check completly failed, manually check if there is update and restart or update and shutdown options"
 override-pendingreboot
 }else {
 Write-host "massive error if you get this lol idk what happend"
 Write-host "even though this output indicates a completly unrecognised reboot reason its probably fine to override and just means i cant code"
 override-pendingreboot
}
}

function override-pendingreboot {
$no = @("no","n")
$yes = @("yes","y")
do
{
    $answ = read-host "Override Pending reboot detection y/n"
}
until($no -contains $answ -or $yes -contains $answ)

if($no -contains $answ)
{
  Throw "This is not an error message just a way to show confirmation the script has ended due to the pending reboot check not being overridden"
}
elseif($yes -contains $answ)
{
    Write-host  "pending reboot detection has been overridden starting main script"
    $global:wasoverridden = "true"
}
}
function open-logs{
read-host "Any Button to continue and open logs"
Explorer.exe C:\HCLOGS314
Read-host "Any Button to proceed back to main menu (after checking logs and correcting any issues)"
} 






Function Bitlocker-auto-detect {
$Global:BitlockerCheck = 0

function testkey-ade {
        $RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
        $Name         = 'PreventAutomaticDeviceEncryption'
        $Value        = '1'
try {
    $key = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker"
    if ($key -and $key.PSObject.Properties.Name -contains "PreventAutomaticDeviceEncryption") {
        Write-host "PreventAutomaticDeviceEncryption already exists setting value to 1"
        set-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -Force 
        $Global:Bitlockercheck = 2
    } else {
        Write-host "creating PreventAutomaticDeviceEncryption subkey and setting value to 1"
        New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 
        $Global:BitlockerCheck = 2 
    }
} catch {
    Write-Error -Category ReadError -Message "BitLocker key exists in the registry, but checking for the presence of 'PreventAutomaticDeviceEncryption' failed."
    $Global:BitlockerCheck = 100
}
}
$ADE = Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker" -PathType Container
if (-not $ade ){
Write-host "bitlocker main regkey not present (need more investigating to know what this means"
Write-Error -category ResourceUnavailable -Message "Bitlocker Key within HKLM:\SYSTEM\CurrentControlSet\Control\ is missing (do not fix this without help unless you think this message is stupid becasue you know what you are doing)"
$Global:BitlockerCheck = 3
}else{
Write-host "bitlocker Main regkey Present"
testkey-ADE
}
}

Function Bitlocker-Overview {
$regeditresult = $null
$skipped = 0 
$bitlockerstatus = get-bitlockervolume | select-object  Mountpoint, VolumeType, VolumeStatus, EncryptionPercentage, CapacityGB


#read-host promt setup
$lines = @(
   "---------------------------------------------------------------------------------------------------------" 
    " "
    "BitLocker is enabled or encryption is currently in progress."
    " "
    "It is not recommended to change the automatic encryption registry key while BitLocker is active."
    " "
    "To proceed with the registry edit, please disable BitLocker and wait for decryption to fully complete."
    " "
   "---------------------------------------------------------------------------------------------------------" 
    "Type y and hit enter to continue with the registry edit."
    " "
    "Type n and hit enter to skip the registry edit."
    " "
)
$formattedText = $lines -join "`n"
#end of read-host prompt setup

if ($bitlockerstatus | Where-Object { $_.VolumeStatus -eq 'FullyEncrypted' -or $_.VolumeStatus -eq 'EncryptionInProgress' -or $_.EncryptionPercentage -gt 0 }) {
    
     $no = @("no","nah","N","n")
     $yes = @("yes","yup","Y","y")

     do
     {
     $answ = read-host "$formattedText"
     }
     until($no -contains $answ -or $yes -contains $answ)

     if($no -contains $answ)
     {
     Write-host "Skipped Bitlocker Auto encrypt REG edit"
     $skipped = "Yes"
     }
     elseif($yes -contains $answ)
     {
     Write-host "Doing Auto Encrypt Reg edit"
     $skipped = "no"
     Bitlocker-auto-detect
     }




} else {

    Write-Output "No volumes with BitLocker enabled or encryption in progress."
}

if ($Global:bitlockercheck -eq 2){
$regeditresult = "Success"
}elseif ($Global:bitlockercheck -eq 100){
$regeditresult = "ERROR : Unable to check if Subkey is Present (read error)"
}elseif ($Global:bitlockercheck -eq 3){
$regeditresult = "ERROR : Bitlocker REG key not present (unkown error lol)"
}else{
$regeditresult = "ERROR: Value of $Global:bitlocker was not 2, 3 or 100 pls zip logs and send them"
}
$output = $bitlockerstatus | Format-Table -AutoSize | Out-String

add-content -path "C:\HCLOGS314\overview.txt" -value "---Bitlocker Stuff---"
#add-content -path "C:\HCLOGS314\overview.txt" -Value "Bitlocker Auto encrypt reg edit skipped = $Skipped"
if ($skipped -eq "no"){
Add-content -path "C:\HCLOGS314\overview.txt" -Value "Registry edit result = $regeditresult"
}
$output | add-content -Path "C:\HCLOGS314\overview.txt"

add-content -path "C:\HCLOGS314\overview.txt" -value "---End of Bitlocker Stuff---"

}








 while ($true) {
    Write-Host "Select an option:"
    Write-Host "1. Healthcheck"
    Write-Host "2. Additional tools"
    Write-Host "3. Nukedesk"
    Write-Host "4. Reg changes for speed"
    Write-Host "5. Exit"
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        1 {
            Write-Host "running healthcheck"
              prep
              folders_prep
              start-transcript -Path "C:\HCLOGS314\full_logs\Full_log.txt"
              check-pendingreboot
              DefenderScanType
              regbackup
              disk_health_check
              hwmonitor
              R_kill
              chkdsk/scan
              get_pcinfo
              Check-WindowsDefenderStatus
              update_and_run_windows_defender
              KVRT
              ADW_malwarebytes
              runsfc
              rundism
              #update_common_apps
              launch_human_apps
              disable_some_things
              wiztree
              webroot
              hmpro
              memdump
              create_overview 
              #Bitlocker-auto-detect
              Bitlocker-Overview
              Open-logs
              Stop-Transcript
            break
        }
        2 {
            Write-Host "additional tools"
            aditionaltools
            Delete-folder
            break
        }
        3 {
            Write-Host "Nukedesk"
            nukedesk
            break
        }
       
        4 {
            Write-Host "Reg changes for speed"
            regchanges
            break
        }
       
        5 {
            Write-Host "Exit"
            Write-host "Cleanup"
            cleanup
            return
        }  
        default {
            Write-Host "Invalid choice. Please enter 1-5"
        }
    }
}
    Read-Host "Press Enter to continue..."
    Write-host "SSD TRIM"
    defrag/trim

