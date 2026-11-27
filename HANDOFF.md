# Housekeeper for Windows — Agent Handoff

## Project Overview
- **Repo / Folder:** `/Users/Morad/C3PO/Housekeeper-Windows` (symlinked to `/Volumes/HDD-C3PO/Projects/Housekeeper-Windows`)
- **GitHub:** `https://github.com/aghamorad/Housekeeper-Windows`
- **Architecture:** .NET 8 (`Housekeeper.Core` cross-platform library + `Housekeeper.Windows` WinForms System Tray + frameless Edge App Mode burgundy Command Deck UI + `Housekeeper.Core.Tests`).
- **CI:** `.github/workflows/build-windows.yml` runs Core tests and publishes a self-contained single-file `Housekeeper.exe` (`Housekeeper-Windows-x64.zip`) on `windows-latest` on every push.

## Current State (2026-11-27)
- Shipped `v0.1.0` with:
  1. **Cloudflare Clean VPN:** Native RFC 7748 X25519 + live WARP registration + DarknessShade `8.6.112.x` endpoints + full QUIC `I1` disguise + Amnezia 3.0/3.1 anti-DPI params, plus Cloudflare API Token verification & concurrent Cloudflare IPv4 TLS Clean IP scanner.
  2. **Clean Up (Safe Quarantine):** Moves Windows `%TEMP%` clutter to `%USERPROFILE%\Housekeeper Quarantine` (never permanently deletes).
  3. **Space Lens, Cloudflare Speed Test, Iranian DNS Switcher, Self-Updater, "Made by Morad" & "More Apps by Morad".**
  4. **Accessibility:** `Ctrl+` / `Ctrl-` / `Ctrl+0` text zoom and Windows System Tray quick-launch menu.
