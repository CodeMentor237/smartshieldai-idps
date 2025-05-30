rule privilege_escalation {
    meta:
        description = "Detects potential privilege escalation attempts"
        severity = "critical"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "PrivEsc"
    strings:
        $sudo_abuse = "sudo -i" nocase
        $sudo_abuse2 = "sudo -s" nocase
        $sudo_abuse3 = "sudo -u root" nocase
        $kernel_exploit = "kernel exploit" nocase
        $kernel_exploit2 = "linux vuln" nocase
        $kernel_exploit3 = "kernel cve" nocase
        $suid_abuse = "chmod u+s" nocase
        $suid_abuse2 = "chmod 4755" nocase
        $suid_abuse3 = "chown setuid" nocase
        $service_exploit = "systemctl start" nocase
        $service_exploit2 = "systemctl enable" nocase
        $service_exploit3 = "service reload" nocase
        $capabilities = "getcap" nocase
        $capabilities2 = "setcap" nocase
        $capabilities3 = "cap_set_proc" nocase
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
        $remote_exec = "psexec" nocase
        $remote_exec2 = "wmic" nocase
        $remote_exec3 = "winrm" nocase
        $remote_exec4 = "wmiexec" nocase
        $remote_copy = "xcopy \\\\" nocase
        $remote_copy2 = "robocopy \\\\" nocase
        $remote_copy3 = "copy smb://" nocase
        $credential_use = "runas" nocase
        $credential_use2 = "impersonate" nocase
        $credential_use3 = "logon" nocase
        $remote_admin = "admin$" nocase
        $remote_admin2 = "c$" nocase
        $remote_admin3 = "ipc$" nocase
        $remote_tools = "putty" nocase
        $remote_tools2 = "rdp" nocase
        $remote_tools3 = "vnc" nocase
        $remote_tools4 = "teamviewer" nocase
        $remote_tools5 = "anydesk" nocase
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
        $sensitive_access = "/etc/shadow" nocase
        $sensitive_access2 = "/etc/passwd" nocase
        $sensitive_access3 = "sam.hive" nocase
        $sensitive_access4 = "ntds.dit" nocase
        $webshell = "php eval" nocase
        $webshell2 = "jsp eval" nocase
        $webshell3 = "asp eval" nocase
        $webshell4 = "aspx eval" nocase
        $config_modify = ".bashrc" nocase
        $config_modify2 = ".bash_profile" nocase
        $config_modify3 = ".profile" nocase
        $config_modify4 = ".zshrc" nocase
        $cron_modify = "crontab" nocase
        $cron_modify2 = "/etc/cron" nocase
        $cron_modify3 = "scheduled tasks" nocase
        $binary_replace = "mv /bin/" nocase
        $binary_replace2 = "cp /sbin/" nocase
        $binary_replace3 = "overwrite system32" nocase
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
        $startup_mod = "/etc/init.d" nocase
        $startup_mod2 = "/etc/systemd" nocase
        $startup_mod3 = "/Library/LaunchDaemons" nocase
        $registry_mod = "CurrentVersion\\Run" nocase
        $registry_mod2 = "UserInitMprLogonScript" nocase
        $registry_mod3 = "WindowsNT\\CurrentVersion\\Winlogon" nocase
        $auth_mod = "/etc/pam.d" nocase
        $auth_mod2 = "/etc/security" nocase
        $auth_mod3 = "/etc/sudoers" nocase
        $schtasks = "schtasks /create" nocase
        $schtasks2 = "schtasks /run" nocase
        $schtasks3 = "at.exe /create" nocase
        $login_hook = "/etc/profile.d" nocase
        $login_hook2 = "/etc/bash.bashrc" nocase
        $login_hook3 = "PowerShell profile.ps1" nocase
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
        $encoded_exec = "base64 decode" nocase
        $encoded_exec2 = "utf-16le convert" nocase
        $encoded_exec3 = "hex decode" nocase
        $memory_exec = "virtualalloc" nocase
        $memory_exec2 = "memcpy" nocase
        $memory_exec3 = "writeprocessmemory" nocase
        $unusual_parent = "cmd.exe parent svchost.exe" nocase
        $unusual_parent2 = "powershell.exe parent lsass.exe" nocase
        $script_exec = "iex" nocase
        $script_exec2 = "invoke-expression" nocase
        $script_exec3 = "eval" nocase
        $script_exec4 = "execscript" nocase
        $alternate_streams = "type :" nocase
        $alternate_streams2 = "more :" nocase
        $alternate_streams3 = "echo ::" nocase
    condition:
        2 of them
}

rule suspicious_process {
    meta:
        description = "Detect suspicious process activity"
        severity = "high"
        category = "process"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $suspicious_cmd = "suspicious command" nocase
        $privilege_esc = "privilege escalation" nocase
        $process_injection = "process injection" nocase
    condition:
        any of them
}

rule file_modification {
    meta:
        description = "Detect suspicious file modifications"
        severity = "medium"
        category = "file"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $system_file = "system file modification" nocase
        $config_change = "configuration change" nocase
        $backdoor = "backdoor installation" nocase
    condition:
        any of them
}

rule user_activity {
    meta:
        description = "Detect suspicious user activity"
        severity = "medium"
        category = "user"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $failed_login = "failed login attempt" nocase
        $sudo_usage = "sudo usage" nocase
        $user_creation = "user creation" nocase
    condition:
        any of them
}