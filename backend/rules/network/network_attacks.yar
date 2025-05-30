rule port_scan_activity {
    meta:
        description = "Detects potential port scanning activity"
        severity = "medium"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $rapid_conn = "port.: [^,]*?([0-9]{1,5})[^\d]+([0-9]{1,5})[^\d]+([0-9]{1,5})" nocase
        $syn_scan = "flags.: (?:[^,]*?SYN){3,}" nocase
    condition:
        any of them
}

rule sql_injection_attempt {
    meta:
        description = "Detects potential SQL injection attempts"
        severity = "high"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $sql1 = "UNION SELECT" nocase
        $sql2 = "OR 1=1" nocase
        $sql3 = "' OR '1'='1" nocase
        $sql4 = "DROP TABLE" nocase
        $sql5 = "information_schema" nocase
        $sql6 = "; --" nocase
    condition:
        any of them
}

rule brute_force_attempt {
    meta:
        description = "Detects potential brute force login attempts"
        severity = "high"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $auth_failed = "Authentication failure" nocase
        $login_failed = "Login failed" nocase
        $invalid_pass = "Invalid password" nocase
        $rapid_auth = "auth" nocase
        $rapid_login = "login" nocase
        $rapid_signin = "signin" nocase
    condition:
        any of them
}

rule command_injection {
    meta:
        description = "Detects command injection attempts"
        severity = "critical"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $cmd1 = "`" nocase
        $cmd2 = ";" nocase
        $cmd3 = "|" nocase
        $shell1 = "bash -i" nocase
        $shell2 = "nc -e" nocase
        $shell3 = "python -c" nocase
        $shell4 = "wget http" nocase
        $shell5 = "curl http" nocase
        $dangerous1 = "/etc/passwd" nocase
        $dangerous2 = "/etc/shadow" nocase
        $dangerous3 = "/bin/sh" nocase
        $dangerous4 = "/bin/bash" nocase
    condition:
        (any of ($cmd*) and any of ($shell*)) or any of ($dangerous*)
}

rule network_port_scan {
    meta:
        description = "Detect port scanning activity"
        severity = "high"
        category = "reconnaissance"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $port_scan = "Nmap scan" nocase
        $masscan = "Masscan" nocase
        $port_sweep = "Port sweep" nocase
    condition:
        any of them
}

rule suspicious_connection {
    meta:
        description = "Detect suspicious network connections"
        severity = "medium"
        category = "suspicious"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $tor_exit = "Tor exit node" nocase
        $known_bad = "Known malicious IP" nocase
        $suspicious_port = "Suspicious port" nocase
    condition:
        any of them
}

rule ddos_attempt {
    meta:
        description = "Detect potential DDoS attempts"
        severity = "high"
        category = "attack"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $syn_flood = "SYN flood" nocase
        $udp_flood = "UDP flood" nocase
        $icmp_flood = "ICMP flood" nocase
    condition:
        any of them
} 