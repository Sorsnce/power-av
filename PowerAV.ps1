###############################################
# Author Trae Horton
# Twitter @sorsnce
###############################################
function Enable-ProcessTrace {            
[CmdLetBinding()]            
param(            
)            
$Query = "Select * From __InstanceCreationEvent within 3 Where TargetInstance ISA 'Win32_Process'"            
$Identifier = "StartProcess"            
$ActionBlock = {  
<#----------------------------------------------------------------------------
LEGAL DISCLAIMER 
This Sample Code is provided for the purpose of illustration only and is not 
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY 
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER 
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a 
nonexclusive, royalty-free right to use and modify the Sample Code and to 
reproduce and distribute the object code form of the Sample Code, provided 
that You agree: (i) to not use Our name, logo, or trademarks to market Your 
software product in which the Sample Code is embedded; (ii) to include a valid 
copyright notice on Your software product in which the Sample Code is embedded; 
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and 
against any claims or lawsuits, including attorneys’ fees, that arise or result 
from the use or distribution of the Sample Code. 
  
This posting is provided "AS IS" with no warranties, and confers no rights. Use 
of included script samples are subject to the terms specified 
at http://www.microsoft.com/info/cpyright.htm. 

Written by Moti Bani - mobani@microsoft.com - (http://blogs.technet.com/b/motiba/) 
With script portions copied from http://psvirustotal.codeplex.com
Reviewed and edited by Martin Schvartzman 
#>
Add-Type -assembly System.Security

function Get-Hash() {

    param([string] $FilePath)
    
    $fileStream = [System.IO.File]::OpenRead($FilePath)
    $hash = ([System.Security.Cryptography.HashAlgorithm]::Create('SHA256')).ComputeHash($fileStream)
    $fileStream.Close()
    $fileStream.Dispose()
    [System.Bitconverter]::tostring($hash).replace('-','')
}


function Query-VirusTotal {

    param([string]$Hash)
    
    $body = @{ resource = $hash; apikey = $VTApiKey }
    $VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
    $AVScanFound = @()

    if ($VTReport.positives -gt 0) {
        foreach($scan in ($VTReport.scans | Get-Member -type NoteProperty)) {
            if($scan.Definition -match "detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})") {
                if($Matches.detected -eq "True") {
                    $AVScanFound += "{0}({1}) - {2}" -f $scan.Name, $Matches.version, $Matches.result
                }
            }
        }
    }

    New-Object –TypeName PSObject -Property ([ordered]@{
        MD5       = $VTReport.MD5
        SHA1      = $VTReport.SHA1
        SHA256    = $VTReport.SHA256
        VTLink    = $VTReport.permalink
        VTReport  = "$($VTReport.positives)/$($VTReport.total)"
        VTMessage = $VTReport.verbose_msg
        Engines   = $AVScanFound
    })
}


function Get-VirusTotalReport {
    
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [String]$VTApiKey,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true, ParameterSetName='byHash')]
        [String[]] $Hash,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='byPath')]
        [Alias('Path', 'FullName')]
        [String[]] $FilePath
        )

    Process {
        
        switch ($PsCmdlet.ParameterSetName) {
            'byHash' {
                $Hash | ForEach-Object {
                    Query-VirusTotal -Hash $_
                }
            }
        
            'byPath' {
                $FilePath | ForEach-Object {
                    Query-VirusTotal -Hash (Get-Hash -FilePath $_) | 
                        Add-Member -MemberType NoteProperty -Name FilePath -Value $_ -PassThru
                }
            }
        }
    }

} 
          
 $e = $event.SourceEventArgs.NewEvent.TargetInstance            
 $ProcessID = ("{0}" -f $e.ProcessID) 
 Write-Host ("{0} {1}" -f $e.Name, $e.ProcessID)    
 $Filelocation = Get-Process | Where ID -eq "$ProcessID" | select -ExpandProperty Path
 # Change the API key to your VirusTotal API
 $API = "zsf56gj14sdgf56h1j56sdgfh1j561dgfh56j1sdf56gj156dgfhj156gh1j56gh1"
 $vtc = Get-VirusTotalReport -VTApiKey $API -FilePath $Filelocation  | out-file "C:\vtlog.txt"
 $VTReport = Get-VirusTotalReport -VTApiKey $API -FilePath $Filelocation  | select -ExpandProperty VTReport
 # Change the level depending on how sensitive you want your email alert to trigger
 # Low = 35
 # Medium = 25
 # High = 15
 # Paranoid = 5
 $level = 5
 if ($VTReport -gt $level)
 {
        # Change the email address to reflect the desired send to
        $recipients = "SecurityTeam@test.com"
        # Change the email address to reflect the desired send from
        $Sender = "VirusDetected@test.com"
        $subject = "Virus Detected for $filelocation"
        $body = (Get-Content "C:\vtlog.txt") -join "`n"
        # Change the following to your SMTP server to send email alerts from the Virustotal report
        $smtpserver = "smtp.test.local"
        send-mailmessage -smtpserver $smtpserver -to $recipients -Subject $subject -from $sender -body $body -Priority High  
 }
 Write-Host $VTReport    
}            
Register-WMIEvent -Query $Query -SourceIdentifier $Identifier -Action $ActionBlock
}
Enable-ProcessTrace
