# SOC-setup
there should be the class file and the "Update__setup_server.ps1" in desktop 
winserver 2022 
open powershell as admin
```
cd "C:\Users\Administrator\Desktop\"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Setup-SOC-WinServer2022.ps1 -SplunkServerIP 192.168.10.1 -SplunkPort 9997

```

then 

host side win 11
there should be the class file and the "host_side_splank.ps1" in desktop

```
cd C:\Users\Administrator\Desktop\
Set-ExecutionPolicy -Scope Process Bypass -Force
.\host_side_splank.ps1

```

