@echo off
cd /d "%~dp0"
set ServiceName=Protector
set DriverFile=%~dp0Protector.sys

:: 检查是否以管理员权限运行
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [Error] 请右键选择 "以管理员身份运行" !
    pause
    exit
)

echo [1/3] 清理旧服务...
sc stop %ServiceName% >nul 2>&1
sc delete %ServiceName% >nul 2>&1

echo [2/3] 创建驱动服务...
:: type= kernel 表示这是个内核驱动
:: binPath 必须是绝对路径
sc create %ServiceName% binPath= "%DriverFile%" type= kernel start= demand
if %errorLevel% neq 0 (
    echo [Error] 创建服务失败！请检查路径或文件名。
    pause
    exit
)

echo [3/3] 启动驱动...
sc start %ServiceName%
if %errorLevel% neq 0 (
    echo.
    echo [Error] 启动失败！常见原因：
    echo 1. 未开启测试模式 (bcdedit /set testsigning on)
    echo 2. 驱动代码有 Bug 初始化失败 (返回了非 STATUS_SUCCESS)
    echo 3. 没有数字签名
) else (
    echo [Success] 驱动已成功加载！
)

pause