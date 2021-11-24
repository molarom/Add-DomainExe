<#
.DESCRIPTION
Attempts to take a program the user specifies and distribute it across a domain environment.
Must be run with domain admin credentials.
 
.PARAMETER FilePath
Full path to an executable the user wishes to distribute.
.EXAMPLE
PS> Add-DomainExe -FilePath "C:\Windows\Temp\saveme.exe" -Username "User" -Password "P@ssw0rd"
#>

function Add-DomainExe {
    # Verify user input for options before script is run.
    param([ValidateScript({ if (-Not ($_ | Test-Path)) {
        throw "File or Folder does not exist. Verify input and run again."
        }
        return $true
        })]$FilePath,
        [parameter(mandatory=$true)]$Username,
        [parameter(mandatory=$true)]$Password,
        $OffLimits

    )

    
    
    # String clean up for later use.
    $inputpath = $FilePath -split "\\"
    $file_split = $inputpath[-1]
    $file_split2 = $file_split -split "\."
    $program = $file_split2[0]
    $prog_ext = $file_split2[-1]

    # Creating temp file for b64 encode and transfer.
    $filetrim = $FilePath.TrimEnd(".$prog_ext")
    $tempFilePath = "$filetrim" + ".temp"
    $tempfile = "$program" + ".temp"

    # Base64 encoding to ensure entire contents are passed over the wire.
    Write-Host "[*] Creating temporary base64 file for transfer..."
    certutil -encode $FilePath $tempFilePath > $null
    $c = Get-Content $tempFilePath
    del $tempFilePath

    # Credential variable without prompt
    $user = $Username
    $pass = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $adm_credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
    
    # Get only the names of every system running windows.
    $computers = Get-ADComputer -Filter 'operatingsystem -like "*windows*" -and enabled -eq "true"' | Select-Object -ExpandProperty Name
    
    foreach($computer in $computers) {
            try {
                #Offlimits
                if ($computer -like $OffLimits) {"[!] $($computer) is offlimits. Ignoring host."} else { 

                # Create a remote PSsession for interaction with the workstation.
                Write-Host "[+] Attempting to connect to: [$computer]..."
                $s = New-PSSession -ComputerName $computer -Credential $adm_credential -ErrorAction Stop

                # Check if the process is running.
                $prog_running = Invoke-Command -Session $s -ScriptBlock { param ($proc) Get-Process $proc -ErrorAction SilentlyContinue} -argumentlist $program
      
                if ( $prog_running -ne $null) {
                    Write-Output "[*] The program is running on [$computer]. No further action necessary."
                }
                else{
                    $host_count += 1
                    # Get the current user's login id.
                    $user_regex = Invoke-Command -Session $s -ScriptBlock { quser } -ErrorAction Stop | ForEach-Object -Process {$_ -replace '\s{2,}',','}
                    $user_object = $user_regex | ConvertFrom-Csv

                    #Getting metrics for number of users.
                    $user_count = $user_object | Measure-Object

                    Write-Host "[+] Found $($user_count.Count) user login(s) on computer."
                    $user_object | ForEach-Object{
                        if ($_.Username -match "adm.*"){
                            Write-Host "[!] Current logged in user is an admin. Ignoring."
                        }
                        else {
                            Write-Host "[+] Placing [$Program] on [$computer] for [$($_.Username)]..."
                            $remoteTempPath = "C:\Users\"+ $_.Username +"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" + $tempfile
                            $remoteHostPath = "C:\Users\"+ $_.Username +"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" + $file_split
                            invoke-command -session $s -script {param($remoteFile,$contents) set-content -path $remoteFile -value $contents} -argumentlist $remoteTempPath,$c -ErrorAction Stop
                            $profile_count += 1
                            Write-Host "[*] Decoding file and cleaning up temporary file..."
                            Invoke-Command -Session $s -script {param($remoteTemp,$remotePath) certutil -decode "$remoteTemp" "$remotePath" > $null; del "$remoteTemp" } -ArgumentList $remoteTempPath,$remoteHostPath -ErrorVariable $registry_err
                            Write-Host "[+] Logging off $($_.Username)..."
                            invoke-command -session $s -script {param ($quser_object) logoff $quser_object.sessionname} -ArgumentList $_
                        }
                    }
                Remove-PSSession $s
                }}
            }
            catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                Write-Host "[!] Unable to authenticate to [$computer]."
                continue
            }
            catch {
                Write-Host "[-] $computer - $($_[0])"
                continue
            }  
        Write-Host ""
        }
    if ($profile_count -gt 0) {Write-Host "[+] Accessed $($host_count) host and installed [$Program] in $($profile_count) Roaming profiles!"} else {Write-Host "[-] [$Program] not installed on any hosts."} 
}

<#
.DESCRIPTION
Remove files placed via Add-DomainExe
#>

function Remove-DomainExe(){
    param(
    [parameter(mandatory=$true)]$HostFile,
    [parameter(mandatory=$true)]$FileName,
    [parameter(mandatory=$true)]$Username,
    [parameter(mandatory=$true)]$Password
    )

    $user = $Username
    $pass = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $adm_credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass

    $hosts = Get-Content $HostFile
    ForEach ($host in $hosts){
        
        $remoteDirectories = 'C:\Users\*'

        $s = New-PSSession -ComputerName $host -Credential $adm_credential -ErrorAction SilentlyContinue
        invoke-command -session $s {Get-ChildItem $remoteDirectories | ForEach-Object {
            $u1 = $_.split('\\')
            $remoteUser = $u1[-1]
            $remoteDirectories = "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
            Write-Host "[+] Removing file for [$remoteUser]"
            Remove-Item $_ + $remoteDirectories + $FileName
            }
        Remove-PSSession $s
        }
   
    }
}
