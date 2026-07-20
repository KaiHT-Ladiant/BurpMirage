@echo off
REM Build BurpMirage English + Korean UI JARs (requires JDK 17+)
if exist gradlew.bat (
  call gradlew.bat jarEn jarKo %*
  exit /b %ERRORLEVEL%
)

where java >nul 2>&1
if errorlevel 1 (
  echo JDK not found on PATH. Install JDK 17+ and set JAVA_HOME.
  exit /b 1
)

where gradle >nul 2>&1
if errorlevel 1 (
  echo Gradle not found. Install Gradle or generate wrapper: 
  echo   gradle wrapper --gradle-version 8.11.1
  exit /b 1
)

gradle jarEn jarKo %*
