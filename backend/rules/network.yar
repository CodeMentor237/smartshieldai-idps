rule suspicious_network_traffic {
    meta:
        description = "Detects potentially suspicious network traffic patterns"
        severity = "medium"
    strings:
        $cmd_shell = "cmd.exe" nocase
        $bash_shell = "/bin/bash" nocase
        $suspicious_port = /port.: [^,]*?(4444|5555|6666|7777|8888)/
    condition:
        any of them
}
