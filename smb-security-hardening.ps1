# PowerShell Interactive Menu for SMB Security Hardening
# Run this script as Administrator

function Check-Settings {
    Write-Host "`nScanning Windows Security Configurations..."
    Write-Host "------------------------------------------------------------"

    # Check SMB Encryption
    $smbEncryption = (Get-SmbServerConfiguration).EncryptData
    Write-Host "SMB Encryption:        " -NoNewline
    if ($smbEncryption) { Write-Host "Enabled (Expected: Enabled)" } else { Write-Host "Disabled (Expected: Enabled)" }

    # Check SMBv1 Status
    $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
    Write-Host "SMBv1:                 " -NoNewline
    if (-not $smb1) { Write-Host "Disabled (Expected: Disabled)" } else { Write-Host "Enabled (Expected: Disabled, Vulnerable)" }

    # Check SMB Signing (Server)
    $smbSigningServer = (Get-SmbServerConfiguration).RequireSecuritySignature
    Write-Host "SMB Signing (Server):  " -NoNewline
    if ($smbSigningServer) { Write-Host "Enabled (Expected: Enabled)" } else { Write-Host "Disabled (Expected: Enabled)" }

    # Check SMB Signing (Client)
    $smbSigningClient = (Get-SmbClientConfiguration).RequireSecuritySignature
    Write-Host "SMB Signing (Client):  " -NoNewline
    if ($smbSigningClient) { Write-Host "Enabled (Expected: Enabled)" } else { Write-Host "Disabled (Expected: Enabled)" }

    # Check NTLMv1 Status
    $ntlmLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    Write-Host "NTLMv1:                " -NoNewline
    if ($ntlmLevel -eq 5) { Write-Host "Blocked (Expected: Blocked)" } elseif ($null -eq $ntlmLevel) { Write-Host "Not Configured (Expected: Blocked)" } else { Write-Host "Allowed (Expected: Blocked, Vulnerable)" }

    # Check NTLM Relay Restriction
    $ntlmRelayPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $ntlmRelayValue = "RestrictSendingNTLMTraffic"
    if (Test-Path $ntlmRelayPath) {
        $ntlmRelay = (Get-ItemProperty -Path $ntlmRelayPath -ErrorAction SilentlyContinue).$ntlmRelayValue
        Write-Host "NTLM Relay:            " -NoNewline
        if ($ntlmRelay -eq 2) { Write-Host "Blocked (Expected: Blocked)" } elseif ($null -eq $ntlmRelay) { Write-Host "Not Configured (Expected: Blocked)" } else { Write-Host "Allowed (Expected: Blocked, Vulnerable)" }
    } else {
        Write-Host "NTLM Relay:            Not Configured (Expected: Blocked)"
    }

    # Check NetBIOS
    $netbios = (wmic nicconfig get TcpipNetbiosOptions | Select-String "2")
    Write-Host "NetBIOS:               " -NoNewline
    if ($netbios) { Write-Host "Disabled (Expected: Disabled)" } else { Write-Host "Enabled (Expected: Disabled, Vulnerable)" }

    # Check LLMNR
    $llmnr = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
    Write-Host "LLMNR:                 " -NoNewline
    if ($llmnr -eq 0) { Write-Host "Disabled (Expected: Disabled)" } elseif ($null -eq $llmnr) { Write-Host "Not Configured (Expected: Disabled)" } else { Write-Host "Enabled (Expected: Disabled, Vulnerable)" }

    # Check Credential Guard
    $credentialGuard = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
    Write-Host "Credential Guard:      " -NoNewline
    if ($credentialGuard -eq 2) { Write-Host "Enabled (Expected: Enabled)" } elseif ($null -eq $credentialGuard) { Write-Host "Not Configured (Expected: Enabled)" } else { Write-Host "Disabled (Expected: Enabled, Vulnerable)" }

    Write-Host "------------------------------------------------------------"
    Write-Host "`nScan Completed. Press Enter to continue..."
    Read-Host
}

function Apply-Fix {
    while ($true) {
        Write-Host "`nSecurity Hardening Menu"
        Write-Host "1 - Enable SMB Encryption"
        Write-Host "2 - Disable SMBv1"
        Write-Host "3 - Enable SMB Signing (Server)"
        Write-Host "4 - Enable SMB Signing (Client)"
        Write-Host "5 - Block NTLMv1"
        Write-Host "6 - Block NTLM Relay"
        Write-Host "7 - Disable NetBIOS"
        Write-Host "8 - Disable LLMNR"
        Write-Host "9 - Enable Credential Guard"
        Write-Host "0 - Back to Main Menu"

        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            "1" { Set-SmbServerConfiguration -EncryptData $true -Force; Write-Host "SMB Encryption Enabled" }
            "2" { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Write-Host "SMBv1 Disabled" }
            "3" { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force; Write-Host "SMB Signing (Server) Enabled" }
            "4" { Set-SmbClientConfiguration -RequireSecuritySignature $true -Force; Write-Host "SMB Signing (Client) Enabled" }
            "5" { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5; Write-Host "NTLMv1 Blocked" }
            "6" { 
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name RestrictSendingNTLMTraffic -Value 2 -PropertyType DWORD -Force
                Write-Host "NTLM Relay Blocked"
            }
            "7" { wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2; Write-Host "NetBIOS Disabled" }
            "8" { Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0; Write-Host "LLMNR Disabled" }
            "9" { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -Value 2; Write-Host "Credential Guard Enabled" }
            "0" { return }
            default { Write-Host "Invalid option. Try again." }
        }
    }
}

while ($true) {
    Clear-Host
    Write-Host "SMB & Security Hardening Menu"
    Write-Host "1 - Scan Security Configuration"
    Write-Host "2 - Apply Fixes"
    Write-Host "3 - Exit"

    $menuChoice = Read-Host "Choose an option"

    switch ($menuChoice) {
        "1" { Check-Settings }
        "2" { Apply-Fix }
        "3" { exit }
        default { Write-Host "Invalid option. Try again." }
    }
}
