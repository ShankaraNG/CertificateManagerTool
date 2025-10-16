@echo off
REM ############################################################################################################
REM ##                                 Certificate Manager                                                    ##
REM ##                                                                                                        ##
REM ## This Script is developed by Shankara N G                                                               ##
REM ## It is to trigger certificate manager application to automate the certificate renewal process           ##
REM ## It will check the certificate in the domain and then if the expiry date is 30 days it will             ##
REM ## trigger the application to renew it                                                                    ##
REM ## This Script is for Windows Terminal                                                                    ##
REM ## Please edit the URL and expiry days                                                                    ##
REM ############################################################################################################

set "URL=yourdomain.com"
set "THRESHOLD_DAYS=30"

REM Get certificate expiry date using PowerShell
for /f "delims=" %%i in ('powershell -Command ^
  "$cert = & openssl s_client -servername %URL% -connect %URL%:443 -showcerts < $null 2>$null | openssl x509 -noout -enddate; ^
   $cert -replace 'notAfter=', ''"') do set "EXPIRY_DATE=%%i"

if "%EXPIRY_DATE%"=="" (
  echo Failed to fetch certificate expiry date
  exit /b 1
)

REM Get expiry and current time as Unix timestamps
for /f %%i in ('powershell -Command "[int][double]::Parse((Get-Date '%EXPIRY_DATE%').ToUniversalTime() - (Get-Date '1970-01-01')).TotalSeconds"') do set "EXPIRY_TS=%%i"
for /f %%i in ('powershell -Command "[int][double]::Parse((Get-Date).ToUniversalTime() - (Get-Date '1970-01-01')).TotalSeconds"') do set "NOW_TS=%%i"

set /a DIFF_DAYS=(%EXPIRY_TS% - %NOW_TS%) / 86400

echo Certificate expires in %DIFF_DAYS% days.

if %DIFF_DAYS% LEQ %THRESHOLD_DAYS% (
  echo Certificate is expiring. Proceeding to renew...
  cd /d E:\PythonCertificates\CertificateManagerTool
  call .venv\Scripts\activate.bat
  python app.pyz
  call .venv\Scripts\deactivate.bat
) else (
  echo Certificate is valid. No renewal needed.
)

