#healthcheck
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
function regbackup {
try {
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
function update_and_run_windows_defender {
Update-MpSignature -Verbose
Start-MpScan -ScanType fullscan -ScanPath $env:SystemDrive -Verbose
remove-mpthreat -verbose
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


}
write-host "$sfcresult" 



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
  regbackup
  disk_health_check
  hwmonitor
  R_kill
  chkdsk/scan
  get_pcinfo
  update_and_run_windows_defender
  KVRT
  ADW_malwarebytes
  runsfc
  rundism
  update_common_apps
  launch_human_apps
  disable_some_things
  wiztree
  webroot
  hmpro
  memdump
  create_overview 
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
    Write-host "cleaning up"
    cleanup
    defrag/trim
