Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "cmd /c pm2 resurrect", 0, True
