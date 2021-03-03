# HAFHunt
Quick powershell script to search for HAFNIUM IOCs for On-Prem Exchange Servers
Leverages IOCs listed in Microsoft and Volexcity articles.

+ Find ASPX files
+ Find known Webshell names
+ List archived files in C:\ProgramData
+ LogSearch OABGeneratorLog (CVE-2021-26858)
+ LogSearch HttpProxy logs (CVE-2021-26855)
+ LogSearch WindowsEvents (CVE-2021-26857)
+ LogSearch Exchange Logs (CVE-2021-27065)
- Does not search shell hashes

This script uses hardcoded directories and filenames provided by microsoft.
It also searches and list all aspx files within the specified directories, based on the  
provided by the Exchange Installation environment variable.

This script also leverages Microsoft's powershell commands to search logs and windows events.

## Sources
https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/

https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
