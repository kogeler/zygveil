@rem SPDX-FileCopyrightText: 2026 kogeler
@rem SPDX-License-Identifier: MIT
@echo off
setlocal
set DIR=%~dp0
if "%DIR%"=="" set DIR=.
set APP_HOME=%DIR%
set CLASSPATH=%APP_HOME%\gradle\wrapper\gradle-wrapper.jar
if not exist "%CLASSPATH%" (
  echo Gradle wrapper JAR is missing. Run the project Make bootstrap on the supported host. 1>&2
  exit /b 1
)
java -classpath "%CLASSPATH%" org.gradle.wrapper.GradleWrapperMain %*
endlocal
