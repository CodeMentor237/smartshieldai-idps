/*
    Version: 1.0.0
    Category: Protocol Attacks
    Description: Rules for detecting protocol-specific attacks and malicious behavior
*/

rule http_attacks {
    meta:
        description = "Detects HTTP-based attacks and suspicious patterns"
        severity = "high"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "HTTP"
    strings:
        $sql_injection = /(union.*select|select.*from|\/\*.*\*\/|\-\-.*$)/i
        $xss_patterns = /(<script>|javascript:|onerror=|onload=|eval\()/i
        $path_traversal = /(\.\.\/|\.\.\%2f|\.\.\\|\%252e\%252e)/i
        $cmd_injection = /(\&.*\||;.*\||`.*`|\$\(.*\))/i
        $file_inclusion = /(include.*\.php|require.*\.php|include.*http|php:\/\/)/i
    condition:
        2 of them
}

rule dns_attacks {
    meta:
        description = "Detects DNS-based attacks and tunneling attempts"
        severity = "high"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "DNS"
    strings:
        $tunneling = /(base32|base64|hex).*\.(com|net|org|info)/i
        $zone_transfer = /(AXFR|IXFR).*request/i
        $cache_poison = /(DNS.*poison|cache.*injection)/i
        $large_query = /([a-zA-Z0-9]{50,})\.(com|net|org|info)/
        $subdomain_flood = /([a-zA-Z0-9]{8,}\.){4,}/
    condition:
        any of them
}

rule smtp_attacks {
    meta:
        description = "Detects SMTP-based attacks and email threats"
        severity = "medium"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "SMTP"
    strings:
        $relay_attempt = /(open.*relay|unauthorized.*relay)/i
        $spam_content = /(viagra|replica|buy.*now|\\$.*million)/i
        $header_spoof = /(Return-Path|From|Reply-To).*\@.*\<.*\>/i
        $attachment_type = /\.(exe|vbs|js|bat|cmd|scr|pif)(\?|$)/i
        $command_verbs = /(VRFY|EXPN|DEBUG|HELP|VERB)/i
    condition:
        2 of them
}

rule ftp_attacks {
    meta:
        description = "Detects FTP-based attacks and unauthorized access attempts"
        severity = "medium"
        version = "1.0.0"
        author = "SmartShieldAI"
        attack_type = "FTP"
    strings:
        $brute_force = /(failed.*login|authentication.*failed)/i
        $anonymous = /(anonymous|ftp).*login/i
        $bounce_attack = /(PORT|EPRT).*([0-9]{1,3}\.){3}[0-9]{1,3}/i
        $sensitive_access = /(passwd|shadow|config|web\.config)/i
        $overflow_attempt = /(.{1000,})/
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
        $heartbleed = /(heartbeat.*request|TLS.*heartbeat)/i
        $poodle = /(SSLv3.*fallback|POODLE.*attack)/i
        $beast = /(CBC.*mode|BEAST.*vulnerability)/i
        $downgrade = /(protocol.*downgrade|fallback.*SCSV)/i
        $weak_cipher = /(RC4|DES|MD5|SHA1)/i
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
        $injection = /(\*|\(\&|\(\||\(\!|\)\))/
        $null_bind = /(anonymous.*bind|unauthenticated.*access)/i
        $search_exploit = /(objectClass=\*|cn=\*)/i
        $attr_overflow = /([a-zA-Z0-9]{100,}=)/
        $bypass_attempt = /(admin.*user|\).*\(not|pass.*admin)/i
    condition:
        2 of them
}