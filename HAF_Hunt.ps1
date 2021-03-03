# Version 4
# Last Updated: 3/3/2021 18:13
# 
#
# + Find ASPX files
# + Find known Webshell names
# + List archived files in C:\ProgramData
# + LogSearch OABGeneratorLog (CVE-2021-26858)
# + LogSearch HttpProxy logs (CVE-2021-26855)
# + LogSearch WindowsEvents (CVE-2021-26857)
# + LogSearch Exchange Logs (CVE-2021-27065)
# - Does not search shell hashes
#
# This script used hardcoded directories and filenames provided by microsoft
# and it also searches for all aspx files within the installation directory 
# provided by the environment variable.
# This script also leverages 4 Microsoft powershell log queries.
#
# https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
# https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/

$IOC1 = @("C:\inetpub\wwwroot\aspnet_client\web.aspx","C:\inetpub\wwwroot\aspnet_client\web.aspx","C:\inetpub\wwwroot\aspnet_client\help.aspx","C:\inetpub\wwwroot\aspnet_client\document.aspx","C:\inetpub\wwwroot\aspnet_client\errorEE.aspx","C:\inetpub\wwwroot\aspnet_client\errorEW.aspx","C:\inetpub\wwwroot\aspnet_client\errorFF.aspx","C:\inetpub\wwwroot\aspnet_client\healthcheck.aspx","C:\inetpub\wwwroot\aspnet_client\aspnet_www.aspx","C:\inetpub\wwwroot\aspnet_client\aspnet_client.aspx","C:\inetpub\wwwroot\aspnet_client\xx.aspx","C:\inetpub\wwwroot\aspnet_client\shell.aspx","C:\inetpub\wwwroot\aspnet_client\aspnet_iisstart.aspx","C:\inetpub\wwwroot\aspnet_client\one.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\web.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\help.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\document.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\errorEE.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\errorEEE.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\errorEW.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\errorFF.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\healthcheck.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\aspnet_www.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\aspnet_client.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\xx.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\shell.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\aspnet_iisstart.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\one.aspx",
"C:\program files\Microsoft\Exchangeweb.aspx",
"C:\program files\Microsoft\Exchangehelp.aspx",
"C:\program files\Microsoft\Exchangedocument.aspx",
"C:\program files\Microsoft\ExchangeerrorEE.aspx",
"C:\program files\Microsoft\ExchangeerrorEEE.aspx",
"C:\program files\Microsoft\ExchangeerrorEW.aspx",
"C:\program files\Microsoft\ExchangeerrorFF.aspx",
"C:\program files\Microsoft\Exchangehealthcheck.aspx",
"C:\program files\Microsoft\Exchangeaspnet_www.aspx",
"C:\program files\Microsoft\Exchangeaspnet_client.aspx",
"C:\program files\Microsoft\Exchangexx.aspx",
"C:\program files\Microsoft\Exchangeshell.aspx",
"C:\program files\Microsoft\Exchangeaspnet_iisstart.aspx",
"C:\program files\Microsoft\Exchangeone.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\web.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\help.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\document.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\errorEE.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\errorEEE.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\errorEW.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\errorFF.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\healthcheck.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\aspnet_www.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\aspnet_client.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\xx.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\shell.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\aspnet_iisstart.aspx",
"C:\inetpub\wwwroot\aspnet_client\system_web\5\FrontEnd\HttpProxy\owa\auth\one.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\web.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\help.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\document.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\errorEE.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\errorEEE.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\errorEW.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\errorFF.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\healthcheck.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\aspnet_www.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\aspnet_client.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\xx.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\shell.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\aspnet_iisstart.aspx",
"C:\Exchange\FrontEnd\HttpProxy\owa\auth\one.aspx", "C:\temp\HAF-test.txt")

Start-Transcript -Path C:\temp\HAFHunt.txt -Append
Write-Host `r`nHAFNIUM - Exchange IOC search V4
Write-Host [+] Script started at (date)
Write-Host ----------`r`n


# Possible paths for Exchange Install
$paths = @(
"FrontEnd\HttpProxy\ecp\auth\",
"FrontEnd\HttpProxy\owa\auth\",
"FrontEnd\HttpProxy\owa\auth\Current\",
"FrontEnd\HttpProxy\owa\auth\")

$MainPath = $env:exchangeinstallpath

# Check to see if the path exists
foreach ($ioc in $IOC1) {
    if ( Test-Path $ioc){ 
	    Write-Host `r`n[!!] IOC DETECTED: $ioc`r`n
		Read-Host
	}else{
	Write-Host No IOC found at: $ioc
	}
}

# Check each path in Install folder for any ASPX files 
foreach ($path in $paths){
	try{
		set-location $MainPath$path
		Write-Host `r`n
		Write-Host	Checking for .aspx files in $MainPath$path
		Write-Host ---------- 
		gci *.aspx -Recurse
		Write-Host [+] Done...
	} catch {
		Write-Host [Error] The Path does not exist
	}
		
}

# Check for suspicious .zip, .rar, and .7z files in C:\ProgramData\, which may indicate possible data exfiltration.
set-location C:\ProgramData\
Write-Host `r`n
Write-Host	Checking for 7z rar and zip files in ProgramData
Write-Host ---------- 
gci *.7z,*.rar,*.zip
Write-Host [+] Done...



# Log checks Below



# CVE-2021-26858 exploitation can be detected via the Exchange log
Write-Host `r`n
Write-Host Checking for CVE-2021-26858 via the exchange log
Write-Host ---------- 
findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"
Write-Host [+] Done...

# CVE-2021-26855 exploitation can be detected via the following Exchange HttpProxy logs
Write-Host `r`n
Write-Host Checking for CVE-2021-26855 via the HttpProxy logs ( This one may take a while... )
Write-Host ---------- 
Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -Filter '*.log').FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox
Write-Host [+] Done...

# CVE-2021-26857 exploitation can be detected via the Windows Application event logs 
Write-Host `r`n
Write-Host Checking for CVE-2021-26857 via Windows Application event logs
Write-Host ---------- 
Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }
Write-Host [+] Done...

# CVE-2021-27065 exploitation can be detected via the following Exchange log files
Write-Host `r`n
Write-Host Checking for CVE-2021-2706 via Exchange log files
Write-Host ---------- 
Select-String -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory'
Write-Host [+] Done...

# Script finished
Write-Host [!] Script Finished: (date)
Stop-Transcript
Write-Host [+] Output saved at C:\temp\HAFHunt.txt
