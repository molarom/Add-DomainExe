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
        [parameter(mandatory=$true)]$Password

    )
    
    $inputpath = $FilePath -split "\\"
    $file_split = $inputpath[-1]
    $program = $file_split -split "\."
    
    # Credential variable without prompt
    $user = $Username
    $pass = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $adm_credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
    
    # Get only the names of every system running windows.
    $computers = Get-ADComputer -Filter 'operatingsystem -like "*windows*" -and enabled -eq "true"' | Select-Object -ExpandProperty Name
    
    foreach($computer in $computers) {
        Write-Host "[+] Attempting to connect to: [$computer]..."
        
        # Check if the process is running.
        $prog_running = Invoke-Command -ComputerName $computer -Credential $adm_credential -ScriptBlock { param ($proc) Get-Process $proc -ErrorAction SilentlyContinue} -argumentlist $program
          
        if ( $prog_running -ne $null) {
            Write-Output "The program is running on [$computer]. No further action necessary."
        }

        else {
            try {
                # Create a remote PSsession for interaction with the workstation.
                Write-Host "[+] Attempting to connect to  [$computer]"
                $s = New-PSSession -ComputerName $computer -Credential $adm_credential -ErrorAction SilentlyContinue

                
                Copy-Item $FilePath -Destination $remoteHostPath -ToSession $s

                try {
                    # Get the current user's login id.
                    $user_regex = quesr | ForEach-Object -Process {'\s{2,}',','}
                    $user_object = $user_regex | ConvertFrom-Csv
                    Write-Host "[+] Found $($user_object.Count) user login(s) on computer."
                    $user_object | ForEach-Object{
                        if ($_.Username -match "adm.*"){
                            Write-Host "[!] Current logged in user is an admin. Ignoring."
                        }
                        else {
                            Write-Host "[+] Placing [$Program] on [$computer] for [$_.Username]..."
                            $remoteHostPath = "C:\Users\"+ $_.Username +"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
                            Copy-Item $FilePath -Destination $remoteHostPath -ToSession $s
                            Write-Host "[+] Logging off $_.Username..."
                            logoff $_.sessionname
                        }
                    }
                }


                catch {
                    if ($_.Exception.Message -match 'No User exists'){
                    Write-Host "[!] No users are logged in. Ignoring."
                }
                else {
                    throw $_.Exception.Message
                }
            }                
                Remove-PSSession $s
            }

            # If can't connect, print a short message.
            catch [System.UnauthorizedAccessException] {
                Write-Warning -Message "[-] Access Denied: [$computer]"
            }
        Write-Host ""
        }
    }
    Write-Host "[+] [$Program] installed on all hosts!"
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

    $hosts = Get-Content $HostFile
    ForEach ($host in $hosts){
        
        $remoteDirectories = 'C:\User*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\'

        $s = New-PSSession -ComputerName $computer -Credential $adm_credential -ErrorAction SilentlyContinue
        invoke-command -session $s {Get-ChildItem $remoteDirectories | ForEach-Object {
            Remove-Item $_ + $FileName
            }
        Remove-PSSession $s
        }
   
    }
}
