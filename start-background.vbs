Set shell = CreateObject("WScript.Shell")
base = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = base
pythonw = base & "\venv\Scripts\pythonw.exe"
If Not CreateObject("Scripting.FileSystemObject").FileExists(pythonw) Then
    pythonw = "pythonw.exe"
End If
shell.Run Chr(34) & pythonw & Chr(34) & " " & Chr(34) & base & "\app.py" & Chr(34), 0, False
