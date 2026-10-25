# Changelog

## 1.2.0 - 2026-10-25

- Added delayed Ethernet disable: the “延迟禁网…” entry in the toolbar and tray creates a one-shot Windows scheduled task that disables all enabled physical Ethernet adapters after 1–10080 minutes.
- The delayed task can be created while the UI is open, survives closing the UI, and appears in “任务与操作历史” with cancel support. It does not auto-restore at the end; restore remains explicit.
- The scheduling service re-checks physical adapters, rejects duplicate pending delayed-network tasks, and records the actual execution result rather than assuming success.
- Added tests for delayed task registration/execution, duplicate rejection, already-disabled rejection, and target labeling (119 tests total).

## 1.1.0 - 2026-10-24

- Added a one-click “禁用网络 / 恢复网络” entry for all physical Ethernet adapters. It uses Windows `NetAdapter`, handles only `MediaType=802.3` physical Ethernet adapters, and persists the adapter list used for restoration.
- Added explicit remote-connection and acknowledgement warnings before disabling the network.
- Added a Windows system-tray icon. Closing the main window now hides to the tray instead of exiting; the tray menu can show the window, toggle Ethernet, or exit.
- Exiting while Ethernet is disabled now offers restore-and-exit, exit-with-network-disabled, or stay in the tray. A forced or crashed process can be recovered by relaunching and using “恢复网络” or by Windows network settings.
- Added four fake-controller tests for the Ethernet disable/restore state machine and failure paths (116 tests total).

## 1.0.1 - 2026-10-23

- Fixed the case where a desktop UI that was already started as administrator still launched a second, non-elevated helper, producing “没有得到管理员权限，已拒绝执行”.
- An elevated desktop UI now reuses its own administrator token and executes the same `NetworkControlService` in-process; no second UAC prompt is required.
- Administrator detection now uses the process token's `TokenElevation` value instead of only `WindowsPrincipal.IsInRole`, so a filtered administrator token is not mistaken for an elevated process.
- Added clearer single-instance guidance: close every existing instance before using “Run as administrator”; a second instance cannot replace a running normal-privilege window automatically.
- Added actionable guidance to the helper rejection message and README troubleshooting.

## 1.0.0 - 2026-10-23

- Initial public release: process/service/TCP/UDP enumeration, Windows Firewall rules, program and network-target blocking, delayed/timed tasks with recovery and history, and a traditional WPF data-grid UI.
- Includes real Firewall and Task Scheduler verification; see `docs/VERIFICATION.md`.
