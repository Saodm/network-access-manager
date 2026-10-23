# Changelog

## 1.0.1 - 2026-10-23

- Fixed the case where a desktop UI that was already started as administrator still launched a second, non-elevated helper, producing “没有得到管理员权限，已拒绝执行”.
- An elevated desktop UI now reuses its own administrator token and executes the same `NetworkControlService` in-process; no second UAC prompt is required.
- Administrator detection now uses the process token's `TokenElevation` value instead of only `WindowsPrincipal.IsInRole`, so a filtered administrator token is not mistaken for an elevated process.
- Added clearer single-instance guidance: close every existing instance before using “Run as administrator”; a second instance cannot replace a running normal-privilege window automatically.
- Added actionable guidance to the helper rejection message and README troubleshooting.

## 1.0.0 - 2026-10-23

- Initial public release: process/service/TCP/UDP enumeration, Windows Firewall rules, program and network-target blocking, delayed/timed tasks with recovery and history, and a traditional WPF data-grid UI.
- Includes real Firewall and Task Scheduler verification; see `docs/VERIFICATION.md`.
