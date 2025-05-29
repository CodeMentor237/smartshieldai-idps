/*
    Version: 1.0.0
    Category: Network Attacks
    Description: Rules for detecting common network-based attacks
*/

rule port_scan_activity {
    meta:
        description = "Detects potential port scanning activity"
        severity = "medium"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $rapid_conn = /port.: [^,]*?([0-9]{1,5})[^\d]+([0-9]{1,5})[^\d]+([0-9]{1,5})/
        $syn_scan = /flags.: (?:[^,]*?SYN){3,}/
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
        $auth_failed = /Authentication failure|Login failed|Invalid password/
        $rapid_auth = /auth|login|signin/i
    condition:
        #auth_failed > 5 or
        #rapid_auth > 10 in last_5_minutes
}

rule command_injection {
    meta:
        description = "Detects command injection attempts"
        severity = "critical"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $cmd1 = /[\x60;|]/  // backtick, semicolon, pipe
        $shell1 = "bash -i" nocase
        $shell2 = "nc -e" nocase
        $shell3 = "python -c" nocase
        $shell4 = "wget http" nocase
        $shell5 = "curl http" nocase
        $dangerous = /\/etc\/passwd|\/etc\/shadow|\/bin\/sh|\/bin\/bash/
    condition:
        $cmd1 and any of ($shell*) or
        $dangerous
}