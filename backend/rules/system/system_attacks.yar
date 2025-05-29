/*
    Version: 1.0.0
    Category: System Attacks
    Description: Rules for detecting system-level attacks and privilege escalation attempts
*/

rule privilege_escalation {
    meta:
        description = "Detects potential privilege escalation attempts"
        severity = "critical"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "PrivEsc"
    strings:
        $sudo_abuse = /(sudo|su)\s+.*(-i|-s|-u\s+root)/i
        $kernel_exploit = /(kernel|linux).*(exploit|vuln|cve|poc)/i
        $suid_abuse = /(chmod|chown).*(u\+s|4755|setuid)/i
        $service_exploit = /(systemctl|service|systemd).*(start|enable|reload)/i
        $capabilities = /(getcap|setcap|cap_set_proc)/i
    condition:
        2 of them
}

rule lateral_movement {
    meta:
        description = "Detects potential lateral movement attempts"
        severity = "high"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "LateralMovement"
    strings:
        $remote_exec = /(psexec|wmic|winrm|wmiexec)/i
        $remote_copy = /(xcopy|robocopy|copy).*(\\\\|smb:\/\/)/i
        $credential_use = /(runas|impersonate|logon|credentials)/i
        $remote_admin = /(admin\$|c\$|ipc\$|\\\\.*\\.*\$)/i
        $remote_tools = /(putty|rdp|vnc|teamviewer|anydesk)/i
    condition:
        2 of them
}

rule file_system_abuse {
    meta:
        description = "Detects suspicious file system operations"
        severity = "medium"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "FileSystem"
    strings:
        $sensitive_access = /(\/etc\/shadow|\/etc\/passwd|sam\.hive|ntds\.dit)/i
        $webshell = /(\.(php|jsp|asp|aspx).*eval\(|\.(php|jsp|asp|aspx).*shell)/i
        $config_modify = /(\.bashrc|\.bash_profile|\.profile|\.zshrc)/i
        $cron_modify = /(crontab|\/etc\/cron|scheduled tasks)/i
        $binary_replace = /(mv|cp|overwrite).*(\/bin\/|\/sbin\/|system32)/i
    condition:
        2 of them
}

rule persistence_mechanism {
    meta:
        description = "Detects attempts to establish persistence"
        severity = "high"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "Persistence"
    strings:
        $startup_mod = /(\/etc\/init\.d|\/etc\/systemd|\/Library\/LaunchDaemons)/i
        $registry_mod = /(CurrentVersion\\Run|UserInitMprLogonScript|WindowsNT\\CurrentVersion\\Winlogon)/i
        $auth_mod = /(\/etc\/pam\.d|\/etc\/security|\/etc\/sudoers)/i
        $schtasks = /(schtasks|at\.exe).*(\/create|\/run|\/query)/i
        $login_hook = /(\/etc\/profile\.d|\/etc\/bash\.bashrc|PowerShell.*profile\.ps1)/i
    condition:
        2 of them
}

rule suspicious_execution {
    meta:
        description = "Detects suspicious process execution patterns"
        severity = "high"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "Execution"
    strings:
        $encoded_exec = /(base64|utf-16le|hex).*(decode|convert)/i
        $memory_exec = /(virtualalloc|memcpy|writeprocessmemory)/i
        $unusual_parent = /(cmd\.exe|powershell\.exe).*(parent).*(svchost\.exe|lsass\.exe)/i
        $script_exec = /(iex|invoke-expression|eval|execscript)/i
        $alternate_streams = /(type|more|echo).*(:|::)/i
    condition:
        2 of them
}