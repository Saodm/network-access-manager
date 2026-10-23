# SystemVerifier (test-only)

This console is a developer verification harness. It calls the production
`NetworkControlService` against the real Windows Firewall and Task Scheduler.

It is NOT part of the desktop application and must not be installed as a
service or scheduled task in normal use.

## What it does

- Creates one outbound block rule for `C:\Windows\System32\notepad.exe`.
- Creates one outbound block rule for the RFC 5737 documentation range
  `203.0.113.0/24`.
- Verifies both rules through the production COM manager and through an
  independent `netsh advfirewall firewall show rule` read.
- Removes both rules and verifies that the managed group is empty.
- Registers, queries and deletes a real one-shot Windows task using the
  production scheduler registrar.
- Exercises delayed block, delayed unblock, timed block, cancel and
  cancel-and-unblock through the production Core execution path.
- Performs safety cleanup in a finally block.

It requires an elevated context. Running it through a temporary elevated test
task is a testing convenience, not the product's privilege model.

## Build and run

```powershell
dotnet build tools\SystemVerifier\SystemVerifier.csproj -c Release
dotnet exec tools\SystemVerifier\bin\Release\net10.0-windows\SystemVerifier.dll --data-dir=C:\temp\nam-verify
```

The process must already be elevated. On a normal desktop, launch the command
from an elevated PowerShell window. The JSON/state and output are written under
`--data-dir`.

## Safety

- The target program is notepad; the target IP range is TEST-NET-3.
- Only rules in group `Network Access Manager 受管规则` with the verifier's
  metadata are touched.
- The verifier has a cleanup path, but inspect the managed group and
  `NAM_Task_*` tasks after a failed run.
- Do not run it on a production machine without understanding that it
  temporarily changes the local firewall and Task Scheduler.
