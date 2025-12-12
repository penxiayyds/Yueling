@echo off
cd /d "%~dp0server" && cargo build
cd /d "%~dp0Yueling" && cargo tauri build
