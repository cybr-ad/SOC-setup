# SOC-setup
first download and extract to desktop [ https://drive.google.com/file/d/1UK3aTyimqMoZ_aL9aP3rkI4uN4TpXJFd/view?usp=sharing ]
location example : C:\Users\Laptop\Desktop\class file\...\..\...


there should be the class file and the "Update__setup_server.ps1" in desktop 
winserver 2022 
open powershell as admin
```
cd "$HOME\Desktop"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Setup-SOC-WinServer2022.ps1 -SplunkServerIP 192.168.10.1 -SplunkPort 9997

```

then 

host side win 11
there should be the class file and the "host_side_splank.ps1" in desktop

```
cd "$HOME\Desktop"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\host_spank_v3.ps1

```

