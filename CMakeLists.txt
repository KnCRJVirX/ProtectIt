cmake_minimum_required(VERSION 3.10)
project(HideIt)

if(MSVC)
    # 覆盖默认的 /MD 和 /MDd 标志
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    
    # 双重保险：强制修改编译器标志变量 (防止 CMake 版本低或策略未生效)
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
    )
    foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()
endif()

# 设置 C++ 标准
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(DRIVER_SOURCES 
    dri_protector.c
    dri_callbacks.c
    dri_notify.c
)
set(CMAKE_C_FLAGS_DEBUG "/Od /Zi")
# 驱动生成
add_executable(Protector ${DRIVER_SOURCES})
target_compile_options(Protector PRIVATE /kernel /GS- /Zl /Od)
target_include_directories(Protector PRIVATE
    "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/km"
)

target_link_libraries(Protector PRIVATE
    "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/km/x64/ntoskrnl.lib"
    "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/km/x64/hal.lib"
)
set_target_properties(Protector PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry /NODEFAULTLIB /MANIFEST:NO /INCREMENTAL:NO /INTEGRITYCHECK"
    RUNTIME_OUTPUT_NAME "Protector"
    SUFFIX ".sys"
)

# 生成 HideWindow.dll
# 这是一个共享库 (DLL)
add_library(HideWindow SHARED HideWindow.c)
set_target_properties(HideWindow PROPERTIES PREFIX "")
# 链接必要的 Windows 库 (User32 用于窗口操作 API)
target_link_libraries(HideWindow PRIVATE user32 kernel32)

# 可执行文件
add_executable(ProtIt main.cpp)
# 链接必要的 Windows 库
target_link_libraries(ProtIt PRIVATE ntdll user32 kernel32 Shlwapi)