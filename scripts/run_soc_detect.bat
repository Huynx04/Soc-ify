@echo off
REM SOC-ify scheduled detection - called by Windows Task Scheduler every 10 min.
REM Runs the detection engine against recent nginx logs and writes findings to siem-findings.
cd /d C:\Users\ADMIN\soc-ify\scripts
set MSYS_NO_PATHCONV=1
E:\anaconda\python.exe apply_rules.py --range now-20m
