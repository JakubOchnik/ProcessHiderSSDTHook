# Windows Process Hider SSDT Hook
In short words: A WDM Windows driver, which hides the user-specified process from the task manager (and probably some other places too). I made it as a university project - kernel mode programming exercise.
## What it does?
It hooks the ZwQuerySystemInformation Windows kernel function. Every time when the system requests a list of currently running processes, the hook function fetches it and just unlinks the process with a user-specified name from the list.
## Where does it work?
Tested on Windows 7 SP1 32-bit. It won't work on 64-bit systems due to the PatchGuard mechanism and lack of 64-bit SSDT exporting by ntoskrnl.exe.