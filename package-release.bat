:: Invoke as package-release.bat <solution-dir> <Debug|Release>

@echo off

if "%1" == "" (
    echo Usage: package-release.bat ^<solution-dir^> ^<Debug^|Release^>
    exit /b 1
)
if "%2" == "" (
    echo Usage: package-release.bat ^<solution-dir^> ^<Debug^|Release^>
    exit /b 1
)

set SOLUTION_DIR=%1

if "%2" == "Debug" (
    set CONFIGURATION=Debug
) else if "%2" == "Release" (
    set CONFIGURATION=Release
)

rmdir /S /Q "%SOLUTION_DIR%\release-files" 2> NUL

set OUTPUT_ROOT_DIR=%SOLUTION_DIR%\release-files\%CONFIGURATION%
set PLUGINS_DIR=%OUTPUT_ROOT_DIR%\nativePC\plugins
set LOADER_DIR=%PLUGINS_DIR%\CSharp\Loader

if "%CONFIGURATION%" == "Debug" (
    echo F | xcopy "%SOLUTION_DIR%\SharpPluginLoader.Bootstrapper\bin\Debug\net8.0\SharpPluginLoader.Bootstrapper.dll" "%LOADER_DIR%\SharpPluginLoader.Bootstrapper.Debug.dll" > nul
    echo F | xcopy "%SOLUTION_DIR%\SharpPluginLoader.Core\bin\Debug\net8.0\SharpPluginLoader.Core.Debug.dll" "%LOADER_DIR%\SharpPluginLoader.Core.Debug.dll" > nul
    echo F | xcopy "%SOLUTION_DIR%\Assets\Default.Debug.bin" "%LOADER_DIR%\Default.Debug.bin" > nul
    echo F | xcopy "%SOLUTION_DIR%\x64\Debug\mhw-cs-plugin-loader.dll" "%OUTPUT_ROOT_DIR%\winmm.dll" > nul
    echo F | xcopy "%SOLUTION_DIR%\mhw-cs-plugin-loader\SharpPluginLoader.runtimeconfig.json" "%LOADER_DIR%\SharpPluginLoader.runtimeconfig.json" > nul
) else if "%CONFIGURATION%" == "Release" (
    echo F | xcopy "%SOLUTION_DIR%\SharpPluginLoader.Bootstrapper\bin\Release\net8.0\SharpPluginLoader.Bootstrapper.dll" "%LOADER_DIR%\SharpPluginLoader.Bootstrapper.dll" > nul
    echo F | xcopy "%SOLUTION_DIR%\SharpPluginLoader.Core\bin\Release\net8.0\SharpPluginLoader.Core.dll" "%LOADER_DIR%\SharpPluginLoader.Core.dll" > nul
    echo F | xcopy "%SOLUTION_DIR%\Assets\Default.bin" "%LOADER_DIR%\Default.bin" > nul
    echo F | xcopy "%SOLUTION_DIR%\x64\Release\mhw-cs-plugin-loader.dll" "%OUTPUT_ROOT_DIR%\winmm.dll" > nul
    echo F | xcopy "%SOLUTION_DIR%\mhw-cs-plugin-loader\SharpPluginLoader.runtimeconfig.json" "%LOADER_DIR%\SharpPluginLoader.runtimeconfig.json" > nul
)

