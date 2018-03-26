# PowerAV
PowerShell script that monitors any executed file and then sends the hash to VirusTotal for Analysis


# Variables to Change
Change the API key to your VirusTotal API  
* $API = "YOUR API KEY" ------- Line 119
***

Change the level depending on how sensitive you want your email alert to trigger
* Low = 35
* Medium = 25
* High = 15
* Paranoid = 5

$level = "NUMBER VALUE ABOVE" ----- Line 127
***

Change the email address to reflect the desired send to  
$recipients = "SecurityTeam@test.com" --------- Line 131
***

Change the email address to reflect the desired send from  
$Sender = "VirusDetected@test.com" ----------- Line 133
***

Change the following to your SMTP server to send email alerts from the Virustotal report  
$smtpserver = "smtp.test.local" ---------- Line 137
