# Protect It

进程保护工具

伪装进程名称、路径，保护进程及线程不被打开句柄。

## 基本用法

- 添加保护进程

    ```
    ProtIt.exe -p -im <ImageName>
    ```

    进程运行后会自动被伪装和保护。

- 自动（录屏中）隐藏窗口

    ```
    ProtIt.exe -hw
    ```

    会循环运行，设置为保护的进程运行时自动注入 `HideWindow.dll` ，使窗口不被录屏，且加上 `WS_EX_TOOLWINDOW` 属性时窗口不在任务栏上显示。
