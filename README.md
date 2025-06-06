# 360hashdump

## 这是一个在360环境下开启核晶状态下进行hashdump的dll脚本文件

### 原理是通过使用创建进程内存快照方式获取lsass内存的hash 并通过自定义的回调函数来处理事件 

### 使用版本win8以上均可（作者在win10 windows server 2016 均可 ）

### 使用命令 rundll32.exe LsassDumper.dll,DumpLsassA C:\output\lsass.dmp
![屏幕截图 2025-06-06 183341](https://github.com/user-attachments/assets/ad6fdd8f-6a31-45b8-9735-afa6ee9e2ac3)
![屏幕截图 2025-06-06 183709](https://github.com/user-attachments/assets/e0d78307-0c6d-4b01-9697-794052651421)

