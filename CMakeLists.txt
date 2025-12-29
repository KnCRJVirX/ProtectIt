cmake_minimum_required(VERSION 3.10)
project(ProtectIt)

# 设置 C++ 标准
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 获取Windows SDK根目录
if(DEFINED ENV{WindowsSdkDir})
    set(WDK_ROOT "$ENV{WindowsSdkDir}")
else()
    message(FATAL_ERROR "环境变量 WindowsSdkDir 未定义！请在 'VS 开发人员命令提示符' 中运行 CMake。")
endif()

# 获取版本号
if(DEFINED ENV{WindowsSdkVersion})
    set(WDK_VER "$ENV{WindowsSdkVersion}")
else()
    set(WDK_VER "${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
endif()

# 去掉版本号末尾可能存在的反斜杠 (VS环境变量有时带\)
string(REGEX REPLACE "\\\\$" "" WDK_VER "${WDK_VER}")

# 3. 拼接路径
set(WDK_INCLUDE "${WDK_ROOT}Include/${WDK_VER}/km")
set(WDK_LIB     "${WDK_ROOT}Lib/${WDK_VER}/km/x64")

message(STATUS "WDK Path: ${WDK_ROOT}")
message(STATUS "WDK Version: ${WDK_VER}")

# 驱动生成 
set(DRIVER_SOURCES dri_protector.c
                   dri_callbacks.c
                   dri_notify.c ) 
set(CMAKE_C_FLAGS_DEBUG "/Od /Zi /D_DEBUG") 
add_executable(Protector ${DRIVER_SOURCES})
target_compile_options(Protector PRIVATE /kernel /GS- /Zl) 
target_include_directories(Protector PRIVATE "${WDK_INCLUDE}")
target_link_libraries(Protector PRIVATE
    "${WDK_LIB}/ntoskrnl.lib"
    "${WDK_LIB}/hal.lib"
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
target_link_libraries(HideWindow PRIVATE user32 kernel32 ntdll)

# 可执行文件
add_executable(ProtIt main.cpp)
# 链接必要的 Windows 库
target_link_libraries(ProtIt PRIVATE ntdll user32 kernel32 Shlwapi)