# script does not need the sleep waits but makes it  less overwhelming for users
$url = "https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe"
Write-host "Teamviewer installer"
start-sleep 3
Write-host "Ending any teamviewer processes"
 $processes = Get-Process | Where-Object { $_.Name -ilike "*teamviewer*" }
    if ($processes) {
        Write-Host "Teamviewer is running. Stopping the process..."
        Start-sleep 2
        $processes | ForEach-Object { Stop-Process -Id $_.Id -Force }
        Write-Host "Teamviewer process has been stopped."
    } else {
        Write-Host "Teamviewer is not running."
    }
start-sleep 2
Write-host "Attempting to install teamviewer using winget"
start-sleep 2
if (Test-Path "C:\Program Files\TeamViewer\TeamViewer.exe"){
 "Teamviewer is already installed, updating..."
 start-sleep 2 
Invoke-WebRequest -uri $url -OutFile $env:TEMP\teamviewer64.exe
start-process -filepath $env:temp\teamviewer64.exe
write-host "Teamviewer installer running"
}else{
try { winget install teamviewer.teamviewer}
catch { "winget not working using hardcoded url" 
start-sleep 2
Invoke-WebRequest -uri $url -OutFile $env:TEMP\teamviewer64.exe
start-process -filepath $env:temp\teamviewer64.exe
write-host "Teamviewer installer running"
}
}
start-sleep 10
exit
