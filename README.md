# PowerShell SMB Security Hardening Script

## Overview
This PowerShell script provides an interactive menu to scan and harden Windows SMB security settings. It helps administrators identify misconfigurations and apply security best practices to protect against SMB-related vulnerabilities.

## Features
- **Scan Security Settings:** Checks SMB encryption, SMBv1 status, SMB signing, NTLM security, NetBIOS, LLMNR, and Credential Guard.
- **Apply Fixes:** Enables security features and disables insecure protocols directly from the menu.
- **User-Friendly:** Interactive menu-driven interface.
- **Automated Hardening:** Implements Microsoft-recommended settings for secure SMB communication.

## Requirements
- Windows Server 2016/2019/2022 or Windows 10/11
- Administrator privileges
- PowerShell 5.1 or later

## Installation
1. Download the script:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/irawanhd/smb-hardening/main/smb-hardening.ps1" -OutFile "smb-hardening.ps1"
