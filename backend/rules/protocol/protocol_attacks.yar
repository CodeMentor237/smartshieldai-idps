rule http_attack {
    meta:
        description = "Detect HTTP-based attacks"
        severity = "high"
        category = "web-attack"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $sql_injection = "SELECT.*FROM" nocase
        $xss = "<script>" nocase
        $path_traversal = "../../" nocase
    condition:
        any of them
}

rule dns_attack {
    meta:
        description = "Detect DNS-based attacks"
        severity = "medium"
        category = "dns-attack"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $dns_tunneling = "DNS tunneling" nocase
        $dns_amplification = "DNS amplification" nocase
        $dns_poisoning = "DNS poisoning" nocase
    condition:
        any of them
}

rule smtp_attack {
    meta:
        description = "Detect SMTP-based attacks"
        severity = "medium"
        category = "mail-attack"
        version = "1.0.0"
        author = "SmartShieldAI"
    strings:
        $spam = "Spam attempt" nocase
        $mail_bomb = "Mail bomb" nocase
        $smtp_relay = "SMTP relay" nocase
    condition:
        any of them
}

rule ftp_attacks {
    meta:
        description = "Detects FTP-based attacks and unauthorized access attempts"
        severity = "medium"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "FTP"
    strings:
        $brute_force = "failed login" nocase
        $brute_force2 = "authentication failed" nocase
        $anonymous = "anonymous login" nocase
        $anonymous2 = "ftp login" nocase
        $bounce_attack = "PORT" nocase
        $bounce_attack2 = "EPRT" nocase
        $sensitive_access = "passwd" nocase
        $sensitive_access2 = "shadow" nocase
        $sensitive_access3 = "config" nocase
        $sensitive_access4 = "web.config" nocase
        $overflow_attempt = /.{1000,}/
    condition:
        2 of them
}

rule ssl_tls_attacks {
    meta:
        description = "Detects SSL/TLS-based attacks and vulnerabilities"
        severity = "critical"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "SSL_TLS"
    strings:
        $heartbleed = "heartbeat request" nocase
        $heartbleed2 = "TLS heartbeat" nocase
        $poodle = "SSLv3 fallback" nocase
        $poodle2 = "POODLE attack" nocase
        $beast = "CBC mode" nocase
        $beast2 = "BEAST vulnerability" nocase
        $downgrade = "protocol downgrade" nocase
        $downgrade2 = "fallback SCSV" nocase
        $weak_cipher = "RC4" nocase
        $weak_cipher2 = "DES" nocase
        $weak_cipher3 = "MD5" nocase
        $weak_cipher4 = "SHA1" nocase
    condition:
        2 of them
}

rule ldap_attacks {
    meta:
        description = "Detects LDAP-based attacks and injection attempts"
        severity = "high"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "LDAP"
    strings:
        $injection = "*"
        $injection2 = "(&"
        $injection3 = "(|"
        $injection4 = "(!"
        $injection5 = "))"
        $null_bind = "anonymous bind" nocase
        $null_bind2 = "unauthenticated access" nocase
        $search_exploit = "objectClass=*" nocase
        $search_exploit2 = "cn=*" nocase
        $attr_overflow = /[a-zA-Z0-9]{100,}=/
        $bypass_attempt = "admin user" nocase
        $bypass_attempt2 = ")(not" nocase
        $bypass_attempt3 = "pass admin" nocase
    condition:
        2 of them
}