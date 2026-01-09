@echo off
setlocal enabledelayedexpansion
chcp 65001 > nul

echo 开始构建流程...

REM 构建后端服务器
echo 1. 构建后端服务器...
cd /d "%~dp0server"
call cargo build
set backend_error=%errorlevel%
echo 后端构建错误码: %backend_error%
if %backend_error% neq 0 (
    echo 后端构建失败
    exit /b %backend_error%
)

echo.
echo 2. 构建前端...
echo 切换到 Yueling 目录...
cd /d "%~dp0Yueling"
echo 当前目录: %cd%
echo 执行 npm run build...
call npm run build
set frontend_error=%errorlevel%
echo 前端构建错误码: %frontend_error%
if %frontend_error% neq 0 (
    echo 前端构建失败
    exit /b %frontend_error%
)

echo.
echo 3. 构建 Tauri 应用...
echo 当前目录: %cd%
echo 执行 cargo tauri build...
call cargo tauri build
set tauri_error=%errorlevel%
echo Tauri 构建错误码: %tauri_error%
if %tauri_error% neq 0 (
    echo Tauri 构建失败
    exit /b %tauri_error%
)

echo.
echo 全部构建完成!
