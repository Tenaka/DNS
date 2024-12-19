<#
            WPAD
            Web Proxy Auto Discovery protocol

            The Web Proxy Auto Discovery (WPAD) protocol assists with the automatic detection of proxy settings for web browsers. 
            Unfortunately, WPAD has suffered from a number of severe security vulnerabilities. Organisations that do not rely on 
            the use of the WPAD protocol should disable it. This can be achieved by modifying each workstation's host file at

            %SystemDrive%\Windows\System32\Drivers\etc\hosts to create the following entry: 255.255.255.255 wpad

            #>

            cd C:\Windows\System32
            $getwpad = Get-Content "C:\Windows\System32\Drivers\etc\hosts" -ErrorAction Stop
            $getwpadstring = $getwpad | Select-String '255.255.255.255 wpad'

            if ($getwpadstring -eq $null)
                {
                    $legProt = "Warning There is no '255.255.255.255 wpad' entry Warning" 
                    $legReg = "C:\Windows\System32\Drivers\etc\hosts\"
                    $trueFalse = "False"
                }
            else
                {
                    $legProt = "There's a 255.255.255.255 wpad entry" 
                    $legReg = "C:\Windows\System32\Drivers\etc\hosts\"
                    $trueFalse = "True"

                }
    
            $newObjLegNIC = New-Object psObject
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragLegNIC += $newObjLegNIC
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            cd HKLM:
            $getLMHostsReg = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -ErrorAction SilentlyContinue
            $enLMHostsReg =  $getLMHostsReg.AutoDetect
    
            if ($enLMHostsReg -eq "0")
                {
                    $legProt = "Disable Automatically Detect Settings - This prevents the use of WPAD for proxy configuration = $enLMHostsReg" 
                    $legReg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.AutoDetect"
                    $trueFalse = "True"
                }
            else
                {
                    $legProt = "Warning Allows Disable Automatically Detect Settings use of WPAD for proxy configuration for the system Warning" 
                    $legReg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.AutoDetect"
                    $trueFalse = "False"
                }
    
            $newObjLegNIC = New-Object psObject
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragLegNIC += $newObjLegNIC
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            cd HKCU:
            $getLMHostsReg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -ErrorAction SilentlyContinue
            $enLMHostsReg =  $getLMHostsReg.AutoDetect
    
            if ($enLMHostsReg -eq "0")
                {
                    $legProt = "Disable Automatically Detect Settings, This prevents the use of WPAD for proxy configuration = $enLMHostsReg" 
                    $legReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.AutoDetect"
                    $trueFalse = "True"
                }
            else
                {
                    $legProt = "Warning Allows Automatically Detect Settings use of WPAD for proxy configuration for the current user Warning" 
                    $legReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.AutoDetect"
                    $trueFalse = "False"
                }
    
            $newObjLegNIC = New-Object psObject
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragLegNIC += $newObjLegNIC
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }


    try
        {     
            cd HKLM:
            $getLMHostsReg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -ErrorAction SilentlyContinue
            $enLMHostsReg =  $getLMHostsReg.AutoConfigURL
    
            if ($enLMHostsReg -eq "$null")
                {
                    $legProt = "Disable Use of PAC (Proxy Auto-Config) Files, Ensure no WPAD or other PAC scripts are set, should be null = $enLMHostsReg" 
                    $legReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.AutoConfigURL"
                    $trueFalse = "True"
                }
            else
                {
                    $legProt = "Warning Allows Disable Use of PAC (Proxy Auto-Config) Files found. WPAD or other PAC scripts are set. Warning" 
                    $legReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.AutoConfigURL"
                    $trueFalse = "False"
                }
    
            $newObjLegNIC = New-Object psObject
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragLegNIC += $newObjLegNIC
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            cd HKLM:
            $getLMHostsReg = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -ErrorAction SilentlyContinue
            $enLMHostsReg =  $getLMHostsReg.EnableAutoProxyResultCache

    
            if ($enLMHostsReg -eq "0")
                {
                    $legProt = "Enforce Policy to Prevent WPAD Usage = $enLMHostsReg" 
                    $legReg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.EnableAutoProxyResultCache
"
                    $trueFalse = "True"
                }
            else
                {
                    $legProt = "Warning Allows Enforce Policy to Prevent WPAD Usage. Warning" 
                    $legReg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.EnableAutoProxyResultCache
"
                    $trueFalse = "False"
                }
    
            $newObjLegNIC = New-Object psObject
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
                Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragLegNIC += $newObjLegNIC
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
