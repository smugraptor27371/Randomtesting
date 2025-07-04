#Requires -runasadministrator

function prep {
$disk = Get-PSDrive C | Select-Object -ExpandProperty Free
$free_space_gb = $disk / 1GB
if ($free_space_gb -lt 15) {
    Write-Host "Less than 15GB of free disk space available."
    Write-Host "Stopping script due to low space"
    stop-transcript
    break
} else {
    Write-Host "There is sufficient disk space available." 
}
Write-output "Checking WMI Repository health..."
$script:wmistate = winmgmt /verifyrepository
if ($script:wmistate -ne "WMI repository is consistent"){
Write-output "WMI repository is not healthy, output of verify command:"
write-output $Script:wmistate
Write-output "collect logs and fix Repository issue, In future this will be automated"
Pause
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
new-item -path "C:\HCLOGS314\Variabledump.txt"
new-item -path "C:\HCLOGS314\globVariabledump.txt"
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
    Write-progress -Activity "Backing up registry" -id "1" -PercentComplete 0 -status "ClassesRoot"
    reg export HKEY_classes_root C:\HCLOGS314\regback\classesroot.reg 1> $null
    Write-progress -Activity "Backing up registry" -id "1" -PercentComplete 20 -status "Current user"
    reg export HKEY_current_user C:\HCLOGS314\regback\currentuser.reg 1>$null
    Write-progress -Activity "Backing up registry" -id "1" -PercentComplete 40 -status "localMachine"
    reg export HKEY_Local_machine C:\HCLOGS314\regback\localmachine.reg 1>$null
    Write-progress -Activity "Backing up registry" -id "1" -PercentComplete 60 -status "Users"
    reg export HKEY_users C:\HCLOGS314\regback\users.reg 1>$null
    Write-progress -Activity "Backing up registry" -id "1" -PercentComplete 80 -status "Current config"
    reg export HKEY_current_config C:\HCLOGS314\regback\currentconfig.reg 1>$null
    Write-progress -Activity "Backing up registry" -id "1" -PercentComplete 100
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
$path = join-path -path "C:\users" -ChildPath "$env:username"
$localteamviewerpath = join-path -path "$path" -childpath "appdata\local\Temp\Teamviewer\Teamviewer_service.exe"
add-content -path "C:\HCLOGS314\Rkillwhitelist.txt" -value "`"$localteamviewerpath`""
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

$Global:overviewpath = "C:\HCLOGS314\overview.txt"
$keypathCpu = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"
$keypathMobo = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
$Global:overviewpath = "C:\HCLOGS314\overview.txt"  # Define your output file path
add-content -path $global:overviewpath -value "Chanel = stable"
add-content -path $global:overviewpath -value "Remember signature based antivirus is becoming less effective and will continue to get less effective"
add-content -path $global:overviewpath -value "At some point more heuristic and behavioural tools will be added and some signature tools may be removed"
add-content -path $Global:overviewpath -value "============================================================= Sys Info"

#MOBO
$FullMoboInfo = Get-ItemProperty -Path $keypathMobo

$BaseBoardProduct = $FullMoboInfo.BaseBoardProduct
$BaseBoardVersion = $FullMoboInfo.BaseBoardVersion
$BIOSVersion = $FullMoboInfo.BIOSVersion
$BIOSReleaseDate = $FullMoboInfo.BIOSReleaseDate
$SystemManufacturer = $FullMoboInfo.SystemManufacturer
$SystemProductName = $FullMoboInfo.SystemProductName

Add-Content -Path $Global:overviewpath -Value "Motherboard Product Number = $BaseBoardProduct"
Add-Content -Path $Global:overviewpath -Value "Motherboard Product Version = $BaseBoardVersion"
Add-Content -Path $Global:overviewpath -Value "BIOS Version = $BIOSVersion"
Add-Content -Path $Global:overviewpath -Value "BIOS Release Date = $BIOSReleaseDate"
Add-Content -Path $Global:overviewpath -Value "Motherboard/Laptop Manufacturer = $SystemManufacturer"
Add-Content -Path $Global:overviewpath -Value "Laptop Product Number = $SystemProductName (In some machines this may be the same as the motherboard's product number)"
Add-Content -Path $Global:overviewpath -Value ""
write-host "Starting DXDIAG to get system info"
$dxdiagOutputPath = "C:\HCLOGS314\full_logs\DXDiag.xml"
Start-Process -FilePath "dxdiag.exe" -ArgumentList "/X $dxdiagOutputPath" -NoNewWindow -Wait

$totalRamNode = Select-Xml -Path $dxdiagOutputPath -XPath "//SystemInformation/Memory"
$availableOsMemoryNode = Select-Xml -Path $dxdiagOutputPath -XPath "//SystemInformation/AvaliableOSMem"
$displayDeviceNodes = Select-Xml -Path $dxdiagOutputPath -XPath "//DisplayDevice"

$nodes0 = Select-Xml -Path $dxdiagoutputpath -XPath "//DxDiagNotes/*"

foreach ($node in $nodes0) {
    $nodeName = $node.Node.Name
    $nodeValue = $node.Node.InnerText
    Add-Content -Path $Global:overviewpath -Value "$nodeName : $nodeValue"
}


#CPU
$FullProcessorInfo = Get-ItemProperty -Path $keypathCpu
$CpuInfo = $FullProcessorInfo.ProcessorNameString
Add-Content -Path $Global:overviewpath -Value "CPU = $CpuInfo"

Add-Content -Path $Global:overviewpath -Value ""
Add-Content -Path $Global:overviewpath -Value "Total RAM: $($totalRamNode.Node.InnerXml)"
Add-Content -Path $Global:overviewpath -Value "Available OS Memory: $($availableOsMemoryNode.Node.InnerXml)"
Add-Content -Path $Global:overviewpath -Value ""


foreach ($node in $displayDeviceNodes) {
    $device = $node.Node
    Add-Content -Path $Global:overviewpath -Value "----------------------"
    Add-Content -Path $Global:overviewpath -Value "Device name: $($device.Cardname)"
    Add-Content -Path $Global:overviewpath -Value "Manufacturer: $($device.Manufacturer)"
    Add-Content -Path $Global:overviewpath -Value "Chip Type: $($device.ChipType)"
    Add-Content -Path $Global:overviewpath -Value "Dedicated Memory: $($device.DedicatedMemory)"
    Add-Content -Path $Global:overviewpath -Value "Shared Memory: $($device.SharedMemory)"
    Add-Content -Path $Global:overviewpath -Value "Device Problem Code: $($device.DeviceProblemCode)"
    Add-Content -Path $Global:overviewpath -Value "WHQL Logo: $($device.DriverWHQLLogo)"
    Add-Content -Path $Global:overviewpath -Value "----------------------"
}
add-content -path $Global:overviewpath -value "============================================================= End Info"
}


function Check-WindowsDefenderStatus {
$overviewpath = "C:\HCLOGS314\overview.txt"
$defenderdisabledoutput = "Get-mpstatus indicates windows defender is disabled. This is usually because of third party antivirus. Skipping scan to prevent error message"
$defenderenabledoutput =  "Get-mpstatus indicates windows defender is enabled. Scan was attempted"
$defenderinvalidoutput =  "Get-MPStatus returned something other than true or false; Skipped the Defender definition update, scan and threat removal"
$Global:DefenderStatus = $null

$Global:DefenderStatus = Get-MpComputerStatus

if ($Global:DefenderStatus.AntispywareEnabled -eq $true) {
Write-host "Defender is Enabled"
add-content -Path "$overviewpath" -value "$defenderenabledoutput"
update-and-run-windows-defender
}elseif ($Global:DefenderStatus.AntispywareEnabled -eq $false){
Write-host "Defender is Disabled"
add-content -Path "$overviewpath" -value "$defenderdisabledoutput"
}else{
Write-Warning "Get-MPStatus returned something other than true or false; Skipping defender definition update and scan"
add-content -Path "$overviewpath" -value "$defenderinvalidoutput"
}
}

function update-and-run-windows-defender {
$Global:Defenderupdatestatus = $null
$Global:Defenderupdateworked = $null
$Global:defenderUpdateerror = $null


$Global:DefenderscanStatus = $null
$Global:DefenderscanWorked = $null
$Global:defenderscanerror = $null


$Global:defenderthreatremovalstatus = $null
$Global:DefenderThreatremovalWorked = $null
$Global:defenderthreatremovalerror = $null

try {
    $Global:Defenderupdatestatus = Update-MpSignature -Verbose 4>&1 
    Write-Host "$Global:Defenderupdatestatus"
    $Global:Defenderupdateworked = $true
} catch {
    $Global:defenderUpdateerror = $_.Exception.Message
    Write-Host "$Global:Defenderupdatestatus"
    Write-Host "Updating Windows Defender failed"
    $Global:DefenderUpdateWorked = $false
}


try {
    $Global:DefenderscanStatus = Start-MpScan -ScanType $Global:Defenderscantype -ScanPath $env:SystemDrive 
    Write-host "Defender Scan Completed"
    $Global:DefenderscanWorked = $true
} catch {
    $global:defenderscanerror = $_.Exception.Message
    Write-Host "$Global:Defenderscanstatus"
    Write-Host "Scan with Windows Defender failed"
    $Global:DefenderscanWorked = $false
}

try {
    $global:defenderthreatremovalstatus = Remove-MpThreat -Verbose 4>&1 
    Write-Host "$global:defenderthreatremovalstatus"
    $Global:DefenderThreatremovalWorked = $true
} catch {
    $global:defenderthreatremovalerror = $_.Exception.Message
    Write-Host "$global:defenderthreatremovalstatus"
    Write-Host "Threat removal with Windows Defender failed"
    $Global:DefenderThreatremovalWorked = $false
}
testing
windows-defender-overview
}

Function windows-defender-overview {
 $overviewpath = "C:\HCLOGS314\overview.txt"
 If($global:Defenderupdateworked -eq $false){
 add-content -Path $overviewpath -value "Windows Defender Definitions update    = $Global:Defenderupdateerror"
 }elseif ($global:Defenderupdateworked -eq $true){
 add-content -path "$overviewpath" -value "Windows Defender Definitions update  = $Global:Defenderupdatestatus"
 }else{
 add-content -path "$overviewpath" -value "Windows Defender Definitions update  = Error (DefenderUpdateWorked global variable was not true or false)"
 }
 
 If($global:Defenderscanworked -eq $false){
 add-content -Path "$overviewpath" -value "Windows Defender scan                = $Global:Defenderscanerror"
 }elseif ($global:Defenderscanworked -eq $true){
 add-content -path "$overviewpath" -value "Windows Defender scan                = Completed"
 }else{
 add-content -path "$overviewpath" -value "Windows Defender scan                = Error (DefenderScanWorked global variable was not true or false)"
 }

If($global:Defenderthreatremovalworked -eq $false){
 add-content -Path "$overviewpath" -value "Windows Defender Threat removal      = $Global:Defenderthreatremovalerror"
 }elseif ($global:DefenderThreatremovalworked -eq $true){
 add-content -path "$overviewpath" -value "Windows Defender Threat removal      = $global:Defenderthreatremovalstatus"
 }else{
 add-content -path "$overviewpath" -value "Windows Defender Threat removal      = Error (DefenderThreatRemovalWorked global variable was not true or false)"
 }
 testing
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
Write-host "running sfc"
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
testing
}

function rundism{
Write-host "running DISM"
$logpath = "C:\HCLOGS314\image_repair_logs"
dism /online /cleanup-image /restorehealth >> $logpath\dism.txt
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
#CHKDSK
if (Test-Path -Path "C:\HCLOGS314\full_logs\chkdsk.txt" ) {
                if (Get-Content -Path "C:\HCLOGS314\full_logs\chkdsk.txt" | Select-String -Pattern "found no problems") {
                 add-content -path "C:\HCLOGS314\overview.txt" -value "Disk corruption = false"
                 } else {
                 add-content -path "C:\HCLOGS314\overview.txt" -value "Disk corruption = true"
                }
} else {
    add-content -path "C:\HCLOGS314\overview.txt" -value "Disk corruption = Log not found check full logs"
}
#CHKDSK
#KVRT
if (Test-Path -Path "C:\HCLOGS314\full_logs\kvrt.txt" ) {   
    if (Get-Content "C:\HCLOGS314\full_logs\kvrt.txt" | Select-String -Pattern "Detected: ([1-9]\d*)") {
   add-content -path "C:\HCLOGS314\overview.txt" -value "KVRT = Issues found check log"
    }else{
    add-content -path "C:\HCLOGS314\overview.txt" -value "KVRT = No Issues found "
    }
}else {
    add-content -path "C:\HCLOGS314\overview.txt" -value "KVRT = Log not found check full log"
}
#KVRT
#ADW
if (Test-Path -Path "C:\HCLOGS314\full_logs\adw.txt" ) {

   if (Get-Content "C:\HCLOGS314\full_logs\adw.txt" | Select-String -Pattern "Total threat items found: ([1-9]\d*)") {
   add-content -path "C:\HCLOGS314\overview.txt" -value "ADW = Found items check logs and clean if needed"
   }else{
   add-content -path "C:\HCLOGS314\overview.txt" -value "ADW = Found no items"
   }
} else {
    add-content -path "C:\HCLOGS314\overview.txt" -value "ADW = Log is not as expected check full logs"
}
#ADW
#RebootOverride
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
#RebootOverride
#Uptime
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
#Uptime
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
#adding wmi
Add-content -path "C:\HCLOGS314\overview.txt" -value "$script:wmistate"
testing
}

function cleanup {
 $processes = Get-Process | Where-Object { $_.Name -ilike "*hdsentinel*" }
    if ($processes) {
        Write-Host "HDSentinel is running. Stopping the process..."
        $processes | ForEach-Object { Stop-Process -Id $_.Id -Force }
        Write-Host "HDSentinel process has been stopped."
    } else {
        Write-Host "HDSentinel is not running."
    }


if (test-path -Path "C:\AdwCleaner"){
Remove-Item -path "C:\AdwCleaner" -recurse -force
}



Remove-item -path "C:\HCLOGS314" -recurse -force
Remove-item -path "$env:TEMP\*" -recurse -force -erroraction SilentlyContinue
New-item -path (get-psreadlineoption).historysavepath -force
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
testing
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
testing
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
Read-host "Any button to retun to main menu, Dont forget to zip the logs if things broke"
} 

function Default-folder-zip {
$no = @("no","nah","nope","n")
$yes = @("yes","yup","yeah","y")
do
{
    $answ = read-host "Use Default Zip location?"
}
until($no -contains $answ -or $yes -contains $answ)

if($no -contains $answ)
{
    Pick-folder
}
elseif($yes -contains $answ)
{
    Write-host "Using Default location C:\HCAIO.zip"
}
}

function pick-folder {
$global:selectedfolder = $null
Add-Type -AssemblyName System.Windows.Forms
$folderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
$folderBrowserDialog.RootFolder = [System.Environment+SpecialFolder]::Desktop
$folderBrowserDialog.Description = "Select a folder For Logs zip file."
$form = New-Object System.Windows.Forms.Form
$form.TopMost = $true
if ($folderBrowserDialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
    $Global:selectedFolder = $folderBrowserDialog.SelectedPath
    Write-Output "Selected folder: $Global:selectedFolder"
} else {
    $global:selectedfolder = "C:\"
    Write-Output "No folder selected"
}
$form.Dispose()
testing
}

function testing {

$excluded = @(
    "args",
    "ConsoleFileName",
    "ExecutionContext",
    "false",
    "HOME",
    "Host",
    "input",
    "MaximumAliasCount",
    "MaximumDriveCount",
    "MaximumErrorCount",
    "MaximumFunctionCount",
    "MaximumVariableCount",
    "MyInvocation",
    "null",
    "PID",
    "PSBoundParameters",
    "PSCommandPath",
    "PSCulture",
    "PSEdition",
    "PSHOME",
    "PSScriptRoot",
    "PSUICulture",
    "PSVersionTable",
    "ShellId",
    "excluded",
    "true",
    "?"
)
$Variabledump = "C:\HCLOGS314\Variabledump.txt"
$variables = Get-Variable -Scope 1 -Exclude $excluded
$outputContent = $variables | ForEach-Object {
    "$($_.Name) = $($_.Value)"
}
Add-Content -Path $variabledump -Value $outputContent
}


function testing-globalscope {
$globvardump = "C:\HCLOGS314\GlobVariabledump.txt"
$variables = Get-Variable -Scope global
$outputContent = $variables | ForEach-Object {
    "$($_.Name) = $($_.Value)"
}
Add-Content -Path $globvardump -Value $outputContent
}


function zip-logs {
Compress-Archive -path "C:\HCLOGS314" -DestinationPath "$Global:selectedfolder\!ZippedHCLOGS.zip"    #! mark is to put it at top of files for ease
} 

Function Bitlocker-autoencrypt{

$KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker\"
$ValueName = "PreventAutomaticDeviceEncryption"
$ValueData = 1

try {Set-ItemProperty -path "$keypath" -name "$ValueName" -value "$ValueData" -type Dword
$Global:preventautoencrypt = "Success"
}
Catch{$Global:preventautoencrypt = $error
write-host "Error occurred trying to set registry key/value full error in log."}


$KeyPath1 = "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker\"
$ValueName1 = "PreventDeviceEncryption"

try {Set-ItemProperty -path "$keypath1" -name "$ValueName1" -value "$ValueData" -type Dword
$Global:preventautoencrypt1 = "Success"
}
Catch{$Global:preventautoencrypt1 = $error
write-host "Error occurred trying to set registry key/value full error in log."}

testing
}
Function Bitlocker-Overview {
    $bitlockerstatus = Get-BitLockerVolume | Select-Object MountPoint, VolumeType, VolumeStatus, EncryptionPercentage, CapacityGB

    $regeditresult = $null
    $skipped = "No"

    if ($bitlockerstatus | Where-Object { $_.VolumeStatus -eq 'FullyEncrypted' -or $_.VolumeStatus -eq 'EncryptionInProgress' -or $_.EncryptionPercentage -gt 0 }) {
        Write-Host "BitLocker is enabled or encryption is currently in progress."
        Write-Host "Proceeding with registry edit."

    } else {
        Write-Output "No volumes with BitLocker enabled or encryption in progress."
    }

    $output = $bitlockerstatus | Format-Table -AutoSize | Out-String
    Add-Content -Path "C:\HCLOGS314\overview.txt" -Value "---Bitlocker Stuff---"
    Add-Content -Path "C:\HCLOGS314\overview.txt" -Value "Registry edit result = $Global:preventautoencrypt"
    $output | Add-Content -Path "C:\HCLOGS314\overview.txt"
    Add-Content -Path "C:\HCLOGS314\overview.txt" -Value "---End of Bitlocker Stuff---"
testing
}

function diskcompat{
$alldisks = get-physicaldisk
$systempart = $env:SystemDrive.TrimEnd(':')
$systemDiskNumber = (Get-Partition | Where-Object { $_.DriveLetter -eq $systempart }).DiskNumber
$systemDisk = $allDisks | Where-Object { $_.DeviceID -eq $systemDiskNumber } | Select-Object MediaType
if ($systemDisk.MediaType -eq "SSD"){
Write-host "OS Drive reported as an SSD" 
}elseif ($systemDisk.mediatype -eq "HDD"){
Write-host "OS Drive reported as a HDD returning to menu" 
diskcompat-prompt
}else{
Write-host "OS Drive reported as $($systemdisk.mediatype) retuning to menu" 
diskcompat-prompt
}
}

function diskcompat-prompt {

$no = @("no","nah","nope","n")
$yes = @("yes","yep","yeah","y")

do
{
    $answ = read-host "Do you want to bypass the drive type check (y/n)?"
}
until($no -contains $answ -or $yes -contains $answ)

if($no -contains $answ)
{
    Write-host "Not Bypassing Drive Compatibility"
    break
}
elseif($yes -contains $answ)
{
    Write-host "Bypassing Drive Compatibility"
}
}

function create-quote {
$quotefolderlocation = "C:\hclogs314\quote"

if (-not(Test-Path C:\HCLOGS314 -PathType Container)) {
    New-Item -path C:\HCLOGS314 -ItemType Directory -force
}

if (-not(Test-Path $quotefolderlocation -PathType Container)) {
    New-Item -path $quotefolderlocation -ItemType Directory -force
}
write-output "Using msinfo to gather hardware environment this may take a a few minutes but the script has not frozen"
Start-Process -FilePath "msinfo32.exe" -ArgumentList "/report C:\hclogs314\quote\fullHWinfo.txt" -Wait
Write-Output "Retreving disk information"
Get-Disk | Select-Object -Property FriendlyName,PartitionStyle,Bustype,healthstatus >> C:\hclogs314\quote\diskinfo.txt

write-output "Retreving Software information, Slow Systems may lag during this"
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$programs = foreach ($path in $regPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -and ($_.SystemComponent -ne 1) -and ($_.ReleaseType -ne "Update")
    } | ForEach-Object {
        $type = if ($_.UninstallString -match "msiexec") {
            "MSI"
        } elseif ($_.UninstallString -match "\.exe") {
            "EXE"
        } else {
            "Unknown"
        }

        [PSCustomObject]@{
            Name         = $_.DisplayName
            Version      = $_.DisplayVersion
            Publisher    = $_.Publisher
            InstallDate  = $_.InstallDate
            Installer    = $type
            RegistryKey  = $_.PSPath
        }
    }
}

Write-output "Exporting to csv"
$exportPath = "C:\hclogs314\quote\softwareinfo.csv"
$programs | Sort-Object Name | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8

$manualquestions = "
#leave blank if not applicable e.g desktop size requirements if we are quoting for a laptop


Extra Items we are quoting for e.g.  wireless keyboard and mouse and external backup drive= 

Are we giving options to different machines e.g. laptop and desktop = 

Wifi needed? = 

use case e.g office and emails or video editing =

desktop size requirements = 

other notes e.g needs 8+usb ports or wants DVD drive = 

Form factor  (Laptop,desktop,AIO) = 

Screen size wanted = 

Screen connector (Display port,vga,etc) =

Other notes on the screen e.g wants speakers on monitor or needs 1440p =

pickup needed? =

dropoff needed? =
"
new-item -Path C:\hclogs314\quote -name manualinfo.txt -ItemType "file" -force
$manualquestions >> C:\hclogs314\quote\manualinfo.txt
Write-Output "waiting for 5 seconds to allow for slow file writes"
start-sleep -Seconds 5
notepad C:\hclogs314\quote\manualinfo.txt
Write-output "When the text file has been completed"
pause
Write-Output "Zipping Quote logs"
Compress-Archive -path "C:\HCLOGS314\quote" -DestinationPath $env:USERPROFILE\desktop\AAZippedquotefiles.zip -force
}

 while ($true) {
    Write-Host "Select an option:"
    Write-Host "1. Healthcheck"
    Write-Host "2. Create Quote file"
    Write-Host "3. zip logs"
    Write-Host "4. Exit"
    
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        1 {
            Write-Host "running healthcheck"
              prep
              diskcompat
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
              KVRT
              ADW_malwarebytes
              runsfc
              rundism
              ##update apps
              launch_human_apps
              disable_some_things
              wiztree
              webroot
              hmpro
              memdump
              create_overview 
              Bitlocker-autoencrypt
              Bitlocker-Overview
              testing-globalscope
              Open-logs
              Stop-Transcript
            break
        }
        2 {
            Write-Host "Create quote file"
            create-quote
        }

        3 {
            test-path -path "C:\HCLOGS314" 
            if (test-path -path "C:\HCLOGS314"){
            default-folder-zip
            zip-logs
            }else { 
            Write-host "could not find Logs (The folder is created at the start of option 1)"
            }
        }
        4{
            Write-Host "Exit"
            Write-host "Cleanup"
            cleanup
            return
        }  
        default {
            Write-Host "Invalid choice. Please enter 1-4"
        }
    }
}
    Read-Host "Press Enter to continue..."
    Write-host "SSD TRIM"
    defrag/trim

