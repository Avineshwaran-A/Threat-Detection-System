/*
 * rules/sample_rules.yar
 * ----------------------
 * Demo YARA rules for HybridShield.
 * Add your real threat intelligence rules in this directory.
 *
 * Rule naming convention: <Category>_<ThreatName>_<Variant>
 */

rule Detect_EICAR_Testfile
{
    meta:
        description = "Detects the standard EICAR anti-malware test string"
        author      = "HybridShield"
        severity    = "high"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule Detect_Suspicious_PowerShell_Download
{
    meta:
        description = "Detects PowerShell commands commonly used to download payloads"
        author      = "HybridShield"
        severity    = "high"

    strings:
        $ps1 = "Invoke-WebRequest"     ascii nocase
        $ps2 = "DownloadString"        ascii nocase
        $ps3 = "IEX("                  ascii nocase
        $ps4 = "Invoke-Expression"     ascii nocase
        $ps5 = "-EncodedCommand"       ascii nocase
        $ps6 = "WebClient"             ascii nocase

    condition:
        2 of ($ps*)
}

rule Detect_Base64_Encoded_PE_Header
{
    meta:
        description = "Detects Base64-encoded Windows PE headers (common payload staging)"
        author      = "HybridShield"
        severity    = "medium"

    strings:
        // "MZ" PE magic encoded in Base64
        $b64_mz_1 = "TVqQAAMAAAAEAAAA" ascii
        $b64_mz_2 = "TVpQAAIAAAAEAAAA" ascii
        $b64_mz_3 = "TVoAAAAAAAAAAAAA" ascii

    condition:
        any of them
}

rule Detect_Linux_ELF_Magic_Wrong_Extension
{
    meta:
        description = "Detects ELF binary magic bytes — extension spoofing is checked by heuristics engine"
        author      = "HybridShield"
        severity    = "high"

    strings:
        $elf_magic = { 7F 45 4C 46 }  // \x7FELF

    condition:
        // Match any file whose first 4 bytes are the ELF magic number.
        // NOTE: 'filename' is NOT a native YARA keyword; extension checking
        // is handled by engines/heuristics.py (MIME spoof detection).
        $elf_magic at 0
}

rule Detect_Reverse_Shell_Patterns
{
    meta:
        description = "Common reverse-shell one-liner patterns in scripts"
        author      = "HybridShield"
        severity    = "critical"

    strings:
        $sh1  = "bash -i >& /dev/tcp/"    ascii nocase
        $sh2  = "/bin/bash -c 'bash -i"   ascii nocase
        $sh3  = "nc -e /bin/sh"           ascii nocase
        $sh4  = "nc -e /bin/bash"         ascii nocase
        $py1  = "socket.connect("         ascii
        $py2  = "os.dup2(s.fileno()"      ascii

    condition:
        any of them
}

rule Detect_Crypto_Ransomware_Strings
{
    meta:
        description = "Common strings found in ransomware source / scripts"
        author      = "HybridShield"
        severity    = "critical"

    strings:
        $r1 = "Your files have been encrypted" ascii nocase
        $r2 = "Bitcoin"                        ascii nocase
        $r3 = ".onion"                         ascii nocase
        $r4 = "AES-256"                        ascii
        $r5 = "pay the ransom"                 ascii nocase
        $r6 = "decrypt your files"             ascii nocase

    condition:
        3 of them
}
