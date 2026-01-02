/*
    YARA-EDR Default Rules
    Example detection rules for demonstration
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        severity = "info"
        author = "YARA-EDR"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule ELF_Packed_UPX
{
    meta:
        description = "Detects UPX packed ELF binaries"
        severity = "low"
        author = "YARA-EDR"

    strings:
        $elf = { 7F 45 4C 46 }
        $upx1 = "UPX!"
        $upx2 = "UPX0"
        $upx3 = "UPX1"

    condition:
        $elf at 0 and any of ($upx*)
}

rule Suspicious_Strings_Generic
{
    meta:
        description = "Generic suspicious string detection"
        severity = "medium"
        author = "YARA-EDR"

    strings:
        $s1 = "rootkit" nocase fullword
        $s2 = "keylogger" nocase fullword
        $s3 = "backdoor" nocase fullword
        $s4 = "meterpreter" nocase fullword
        $s5 = "mimikatz" nocase fullword

    condition:
        2 of them
}

rule CryptoMiner_Indicators
{
    meta:
        description = "Cryptocurrency mining indicators"
        severity = "high"
        author = "YARA-EDR"

    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $s3 = "xmrig" nocase fullword
        $s4 = "cryptonight" nocase fullword
        $s5 = "randomx" nocase fullword

    condition:
        2 of them
}

rule Ransomware_Indicators
{
    meta:
        description = "Ransomware string indicators"
        severity = "critical"
        author = "YARA-EDR"

    strings:
        $s1 = "Your files have been encrypted" nocase
        $s2 = "decrypt your files" nocase
        $s3 = "bitcoin wallet" nocase
        $s4 = "pay ransom" nocase
        $s5 = ".onion" nocase

    condition:
        2 of them
}
