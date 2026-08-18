' SOC-ify hidden detection wrapper
' Runs run_soc_detect.bat without showing a console window.
' Called by Windows Task Scheduler (SOC_Detect) every 10 minutes.
' Standard approach: WScript.Shell.Run with window style 0 (hidden).
Dim shell
Set shell = CreateObject("WScript.Shell")
On Error Resume Next
shell.Run """C:\Users\ADMIN\soc-ify\scripts\run_soc_detect.bat""", 0, True
Set shell = Nothing
