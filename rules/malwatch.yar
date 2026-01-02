/*
    Malwatch Signatures for YARA-EDR
    Source: https://github.com/defended-net/malwatch-signatures

    Contains rules from:
    - defended.net (roscoe skeens)
    - rfxn (ryan macdonald)
    - ruppde (arnim rupp)
*/

// =============================================================================
// Backdoor Detection (defended.net)
// =============================================================================

rule bd_php_anonfox_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "eval hex"
    severity = "high"
    category = "backdoor"

  strings:
    $h1 = { 68 65 78 64 65 63 [0-10] 28 [0-10] 73 75 62 73 74 72 }
    $h2 = { 73 74 72 6C 65 6E [0-10] 28 [0-10] 74 72 69 6D }
    $h3 = { 70 61 63 6B [0-10] 28 [0-10] 22 [0-10] ?? [0-10] 22 }

  condition:
    all of them
}

rule bd_php_eval_gz_b64_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "eval gz b64 hex"
    severity = "high"
    category = "backdoor"

  strings:
    $s1 = "6576616C28677A756E636F6D7072657373286261736536345F6465636F64652827" fullword ascii

  condition:
    $s1
}

rule bd_php_rce_stream_sglobal_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "rce stream sglobal"
    severity = "critical"
    category = "backdoor"

  strings:
    $s1 = "$_GET"
    $s2 = "stream_wrapper_register"
    $s3 = "fopen"

  condition:
    all of them
}

rule bd_php_rce_assert_sglobal_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "rce assert sglobal"
    severity = "critical"
    category = "backdoor"

  strings:
    $h1 = { 61 73 73 65 72 74 [0-10] 28 [0-10] 24 5F }

  condition:
    $h1
}

rule bd_php_rce_cback_sglobal_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "rce cback sglobal"
    severity = "critical"
    category = "backdoor"

  strings:
    $r1 = /(array_(filter|walk|udiff)|(u|ua|uk)sort)[ \t]{,8}\([ \t]{,8}\[\$(GLOBALS|_)/
    $r2 = /(call_user_func|register_shutdown_function)[ \t]{,8}\(.{1,16}\[?\$(GLOBALS|_)[CFGPRS]/

  condition:
    any of them
}

rule bd_php_rce_bticks_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "rce bticks"
    severity = "high"
    category = "backdoor"

  strings:
    $r1 = /`[ \t]{0,8}\$/
    $s1 = "<?php"

  condition:
    $s1 in (0..8) and
    $r1 and
    filesize < 512
}

rule bd_php_cback_xpath_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "cback xpath"
    severity = "high"
    category = "backdoor"

  strings:
    $s1 = "php:functionString"

  condition:
    $s1
}

rule bd_php_cback_xslt_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "cback xslt"
    severity = "high"
    category = "backdoor"

  strings:
    $h1 = { 2D 3E [0-10] 72 65 67 69 73 74 65 72 50 48 50 46 75 6E 63 74 69 6F 6E 73 }

  condition:
    $h1
}

// =============================================================================
// Exploit Detection (defended.net)
// =============================================================================

rule exp_php_addr_mask_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "addr mask"
    severity = "critical"
    category = "exploit"

  strings:
    $s1 = "0xfffffffffffff000"

  condition:
    $s1
}

rule exp_php_heap_groom_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "heap groom"
    severity = "critical"
    category = "exploit"

  strings:
    $s1 = "ZEND_DEBUG_BUILD"
    $s2 = "0x60"

  condition:
    all of them
}

// =============================================================================
// Webshell Detection (defended.net)
// =============================================================================

rule ws_php_exec_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "webshell exec"
    severity = "critical"
    category = "webshell"

  strings:
    $s1 = "<?php"
    $s2 = "$_POST"
    $s3 = "$_GET"
    $s4 = "<form" nocase
    $s5 = "socket_accept" nocase
    $s6 = "socket_bind" nocase
    $r1 = /(^|shell_|[^\w:])exec[ \t]{,4}\(/ nocase
    $r2 = /(^|[^\w])proc_open[ \t]{,4}\(/ nocase
    $r3 = /(^|[^\w])popen[ \t]{,4}\(/ nocase
    $r4 = /(^|[^\w])passthru[ \t]{,4}\(/ nocase
    $r5 = /(^|[^\w])system[ \t]{,4}\(\s?[\$\'\"]/ nocase
    $r6 = /(^|[^\w])eval[ \t]{,4}\(/ nocase

  condition:
    $s1 and
    any of ($s2, $s3, $s4, $s5, $s6) and
    any of ($r*)
}

// =============================================================================
// IOC Detection - Obfuscation Patterns (defended.net)
// =============================================================================

rule ioc_php_obf_comments_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf comments"
    severity = "medium"
    category = "obfuscation"

  strings:
    $r1 = /\/\*\S{1,25}\*\//
    $s1 = "<?php"

  condition:
    $s1 in (0..8) and
    #r1 > 1 and
    @r1[2] - (@r1[1] + !r1[1]) <= 64
}

rule ioc_php_obf_comments_1 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf comments"
    severity = "medium"
    category = "obfuscation"

  strings:
    $h1 = { (0D 0A | 0A) 2E 20[0-10] (2F 2F | 2F 2A) }

  condition:
    $h1
}

rule ioc_php_obf_hex_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf hex"
    severity = "medium"
    category = "obfuscation"

  strings:
    $r1 = /\\x[0-9a-fA-F]{2}\\\d{2,3}/
    $s1 = "<?php"

  condition:
    $s1 in (0..8) and
    $r1
}

rule ioc_php_obf_chevrons_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf chevrons"
    severity = "medium"
    category = "obfuscation"

  strings:
    $r1 = /(<[\da-fA-F]{2}>){2}/

  condition:
    $r1
}

rule ioc_php_obf_octals_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf octals"
    severity = "medium"
    category = "obfuscation"

  strings:
    $r1 = /\\[0-7]{3}/
    $s1 = "<?php"
    $s2 = "preg_match"
    $s3 = "\\000-"

  condition:
    $s1 in (0..8) and
    #r1 > 2 and
    @r1[2] - (@r1[1] + !r1[1]) <= 12 and
    not any of ($s2, $s3)
}

rule ioc_php_obf_concats_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf concats"
    severity = "medium"
    category = "obfuscation"

  strings:
    $r1 = /\$\w{1,10}\{\d{1,2}\}\./

  condition:
    #r1 > 3
}

rule ioc_php_obf_concats_incr_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf concats incr"
    severity = "medium"
    category = "obfuscation"

  strings:
    $r1 = /(\$\w{,8}\+\+;){2}/

  condition:
    $r1
}

rule ioc_php_obf_concats_name_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf concats name"
    severity = "medium"
    category = "obfuscation"

  strings:
    $r1 = /(\s{,4}\.\s{,4}['"][a-zA-Z0-9_]{1,16}['"]){3}/

  condition:
    $r1
}

rule ioc_php_obf_scoped_sglobal_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf scoped sglobal"
    severity = "high"
    category = "obfuscation"

  strings:
    $h1 = { 24 5F 53 45 52 56 45 52 [0-10] 5B [0-10] 5F [0-8] 3A 3A }

  condition:
    $h1
}

rule ioc_php_obf_xor_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf xor"
    severity = "high"
    category = "obfuscation"

  strings:
    $s1 = "<?php"
    $r1 = /\beval[ \t]{0,8}\([^)]/
    $r2 = /\bstrrev/
    $r3 = /\bstr_rot13/
    $r4 = /\bhex2bin/
    $r5 = /\bconvert_uudecode/

  condition:
    $s1 in (0..8) and
    $r1 and
    any of ($r2, $r3, $r4, $r5)
}

rule ioc_php_ip_fget_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "ip fget"
    severity = "high"
    category = "ioc"

  strings:
    $r1 = /file_get_contents\s{,4}\(\s{,4}"https?:\/\/(\d{1,3}\.){3}/

  condition:
    $r1
}

rule ioc_php_dropper_small_upload_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "dropper small upload"
    severity = "high"
    category = "dropper"

  strings:
    $s1 = "$_POST"
    $s2 = "$_GET"
    $s3 = "$_REQUEST"
    $s4 = "$_FILES"
    $s5 = "<form" nocase
    $s6 = "file_get_contents" nocase
    $s7 = "file_put_contents" nocase
    $s8 = "move_uploaded_file" nocase
    $s9 = "fwrite" nocase

  condition:
    any of ($s1, $s2, $s3, $s4, $s5, $s6) and
    any of ($s7, $s8, $s9) and
    filesize < 1024
}

rule ioc_php_artifact_sys_cfg_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "artifact sys cfg"
    severity = "medium"
    category = "ioc"

  strings:
    $s1 = "<?php"
    $s2 = "/etc/passwd"
    $s3 = "/etc/hosts"
    $s4 = "/etc/named.conf"

  condition:
    $s1 in (0..8) and
    any of ($s2, $s3, $s4)
}

rule ioc_js_obf_b64_redir_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf b64 redir"
    severity = "medium"
    category = "obfuscation"

  strings:
    $s1 = "d2luZG93LmxvY2F0aW9u"

  condition:
    $s1
}

rule ioc_js_obf_b64_inj_0 {
  meta:
    author = "roscoe skeens (defended.net)"
    license = "https://creativecommons.org/licenses/by-nc-sa/4.0"
    description = "obf b64 inj"
    severity = "medium"
    category = "obfuscation"

  strings:
    $s1 = "ZG9jdW1lbnQud3JpdGU"

  condition:
    $s1
}

// =============================================================================
// WordPress wp-vcd Malware (rfxn)
// =============================================================================

rule backdoor_php_wpvcd_tempexecution_0 {
  meta:
    author = "ryan macdonald (rfxn)"
    license = "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"
    description = "associated with wp-vcd"
    severity = "critical"
    category = "backdoor"

  strings:
    $re = /extract\s*\(\s*wp_temp_setupx?\s*\(\s*\$\w+\s*\)\s*\)/ nocase

  condition:
    $re
}

rule backdoor_php_wpvcd_divcodename_0 {
  meta:
    author = "ryan macdonald (rfxn)"
    license = "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"
    description = "associated with wp-vcd"
    severity = "critical"
    category = "backdoor"

  strings:
    $re = /\$div_code_name\s*\=\s*['"]wp_vcd['"];/ nocase

  condition:
    $re
}

rule backdoor_php_wpvcd_deployer_0 {
  meta:
    author = "ryan macdonald (rfxn)"
    license = "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"
    description = "associated with wp-vcd"
    severity = "critical"
    category = "backdoor"

  strings:
    $re = /strpos\s*\(\s*\$\w{1,40}\s*,\s*['"]WP_V_CD['"]\s*\)\s*===\s*false/ nocase

  condition:
    $re
}

rule ioc_php_wpvcd_prependedinclude_0 {
  meta:
    author = "ryan macdonald (rfxn)"
    license = "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"
    description = "associated with wp-vcd"
    severity = "high"
    category = "ioc"

  strings:
    $re = /^\<\?php\s+if\s*\(\s*file_exists\s*\(\s*dirname\s*\(\s*__FILE__\s*\)\s*\.\s*['"][^'"]+['"]\s*\)\s*\)\s*(include|require)(_once)?\s*\(\s*dirname\s*\(\s*__FILE__\s*\)\s*\.\s*['"][^'"]+['"]\s*\)\s*\;\s*\?\>\s*\<\?/ nocase

  condition:
    $re
}

rule spam_php_wpvcd_contentinjection_0 {
  meta:
    author = "ryan macdonald (rfxn)"
    license = "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"
    description = "associated with wp-vcd"
    severity = "high"
    category = "spam"

  strings:
    $re = /\$ip\s*=\s*\@file_get_contents\s*\(\s*ABSPATH\s*\.\s*['"]wp\-includes\/wp\-feed\.php['"]/ nocase

  condition:
    $re
}

// =============================================================================
// Base64 Encoded Webshells (arnim rupp)
// =============================================================================

rule webshell_php_base64_enc_0 {
  meta:
    author = "arnim rupp"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    description = "obfuscated base64"
    severity = "critical"
    category = "webshell"

  strings:
    // decoder
    $decoder1 = "base64_decode" fullword nocase wide ascii
    $decoder2 = "openssl_decrypt" fullword nocase wide ascii

    // exec
    $exec1 = "leGVj" wide ascii
    $exec2 = "V4ZW" wide ascii
    $exec3 = "ZXhlY" wide ascii
    $exec4 = "UAeABlAGMA" wide ascii
    $exec5 = "lAHgAZQBjA" wide ascii
    $exec6 = "ZQB4AGUAYw" wide ascii

    // shell_exec
    $shell1 = "zaGVsbF9leGVj" wide ascii
    $shell2 = "NoZWxsX2V4ZW" wide ascii
    $shell3 = "c2hlbGxfZXhlY" wide ascii
    $shell4 = "MAaABlAGwAbABfAGUAeABlAGMA" wide ascii
    $shell5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA" wide ascii
    $shell6 = "cwBoAGUAbABsAF8AZQB4AGUAYw" wide ascii

    // passthru
    $passthru1 = "wYXNzdGhyd" wide ascii
    $passthru2 = "Bhc3N0aHJ1" wide ascii
    $passthru3 = "cGFzc3Rocn" wide ascii
    $passthru4 = "AAYQBzAHMAdABoAHIAdQ" wide ascii
    $passthru5 = "wAGEAcwBzAHQAaAByAHUA" wide ascii
    $passthru6 = "cABhAHMAcwB0AGgAcgB1A" wide ascii

    // system
    $system1 = "zeXN0ZW" wide ascii
    $system2 = "N5c3Rlb" wide ascii
    $system3 = "c3lzdGVt" wide ascii
    $system4 = "MAeQBzAHQAZQBtA" wide ascii
    $system5 = "zAHkAcwB0AGUAbQ" wide ascii
    $system6 = "cwB5AHMAdABlAG0A" wide ascii

    // popen
    $popen1 = "wb3Blb" wide ascii
    $popen2 = "BvcGVu" wide ascii
    $popen3 = "cG9wZW" wide ascii
    $popen4 = "AAbwBwAGUAbg" wide ascii
    $popen5 = "wAG8AcABlAG4A" wide ascii
    $popen6 = "cABvAHAAZQBuA" wide ascii

    // proc_open
    $proc_open1 = "wcm9jX29wZW" wide ascii
    $proc_open2 = "Byb2Nfb3Blb" wide ascii
    $proc_open3 = "cHJvY19vcGVu" wide ascii
    $proc_open4 = "AAcgBvAGMAXwBvAHAAZQBuA" wide ascii
    $proc_open5 = "wAHIAbwBjAF8AbwBwAGUAbg" wide ascii
    $proc_open6 = "cAByAG8AYwBfAG8AcABlAG4A" wide ascii

    // pcntl_exec
    $pcntl1 = "wY250bF9leGVj" wide ascii
    $pcntl2 = "BjbnRsX2V4ZW" wide ascii
    $pcntl3 = "cGNudGxfZXhlY" wide ascii
    $pcntl4 = "AAYwBuAHQAbABfAGUAeABlAGMA" wide ascii
    $pcntl5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA" wide ascii
    $pcntl6 = "cABjAG4AdABsAF8AZQB4AGUAYw" wide ascii

    // eval
    $eval1 = "ldmFs" wide ascii
    $eval2 = "V2YW" wide ascii
    $eval3 = "ZXZhb" wide ascii
    $eval4 = "UAdgBhAGwA" wide ascii
    $eval5 = "lAHYAYQBsA" wide ascii
    $eval6 = "ZQB2AGEAbA" wide ascii

    // assert
    $assert1 = "hc3Nlcn" wide ascii
    $assert2 = "Fzc2Vyd" wide ascii
    $assert3 = "YXNzZXJ0" wide ascii
    $assert4 = "EAcwBzAGUAcgB0A" wide ascii
    $assert5 = "hAHMAcwBlAHIAdA" wide ascii
    $assert6 = "YQBzAHMAZQByAHQA" wide ascii

    // false positives - execu
    $fp_execu1 = "leGVjd" wide ascii
    $fp_execu2 = "V4ZWN1" wide ascii
    $fp_execu3 = "ZXhlY3" wide ascii

    // false positives - esystem
    $fp_esystem1 = "lc3lzdGVt" wide ascii
    $fp_esystem2 = "VzeXN0ZW" wide ascii
    $fp_esystem3 = "ZXN5c3Rlb" wide ascii

    // false positives - opening
    $fp_opening1 = "vcGVuaW5n" wide ascii
    $fp_opening2 = "9wZW5pbm" wide ascii
    $fp_opening3 = "b3BlbmluZ" wide ascii

  condition:
    any of ( $decoder* ) and
    (
      ( any of ( $exec* ) and not any of ( $fp_execu* ) ) or
      any of ( $shell* ) or
      any of ( $passthru* ) or
      ( any of ( $system* ) and not any of ( $fp_esystem* ) ) or
      ( any of ( $popen* ) and not any of ( $fp_opening* ) ) or
      any of ( $proc_open* ) or
      any of ( $pcntl* ) or
      any of ( $eval* ) or
      any of ( $assert* )
    )
}
