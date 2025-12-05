@echo off
set ServiceName=Protector

:: 检查管理员权限
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [Error] 请以管理员身份运行!
    pause
    exit
)

echo 正在停止服务...
sc stop %ServiceName%

echo 正在删除服务...
sc delete %ServiceName%

echo [Done] 卸载完成。
pause