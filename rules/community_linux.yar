rule LinuxBew: MALW
{
	meta:
		description = "Linux.Bew Backdoor"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-07-10"
		version = "1.0"
		MD5 = "27d857e12b9be5d43f935b8cc86eaabf"
		SHA256 = "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06"
	strings:
		$a = "src/secp256k1.c"
		$b = "hfir.u230.org"
		$c = "tempfile-x11session"
	condition:
		all of them
}
rule LinuxHelios: MALW
{
	meta:
		description = "Linux.Helios"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-10-19"
		version = "1.0"
		MD5 = "1a35193f3761662a9a1bd38b66327f49"
		SHA256 = "72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719"
	strings:
		$a = "LIKE A GOD!!! IP:%s User:%s Pass:%s"
		$b = "smack"
		$c = "PEACE OUT IMMA DUP\n"
	condition:
		all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// Linux/Moose yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

private rule is_elf
{
    strings:
        $header = { 7F 45 4C 46 }

    condition:
        $header at 0
}

rule moose
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2015/04/21"
        Description = "Linux/Moose malware"
        Reference   = "http://www.welivesecurity.com/wp-content/uploads/2015/05/Dissecting-LinuxMoose.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s0 = "Status: OK"
        $s1 = "--scrypt"
        $s2 = "stratum+tcp://"
        $s3 = "cmd.so"
        $s4 = "/Challenge"
        $s7 = "processor"
        $s9 = "cpu model"
        $s21 = "password is wrong"
        $s22 = "password:"
        $s23 = "uthentication failed"
        $s24 = "sh"
        $s25 = "ps"
        $s26 = "echo -n -e "
        $s27 = "chmod"
        $s28 = "elan2"
        $s29 = "elan3"
        $s30 = "chmod: not found"
        $s31 = "cat /proc/cpuinfo"
        $s32 = "/proc/%s/cmdline"
        $s33 = "kill %s"

    condition:
        is_elf and all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule LinuxAESDDoS
{
    meta:
	Author = "@benkow_"
	Date = "2014/09/12"
	Description = "Strings inside"
        Reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "3AES"
        $b = "Hacker"
        $c = "VERSONEX"

    condition:
        2 of them
}

rule LinuxBillGates 
{
    meta:
       Author      = "@benkow_"
       Date        = "2014/08/11" 
       Description = "Strings inside"
       Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3429" 

    strings:
        $a= "12CUpdateGates"
        $b= "11CUpdateBill"

    condition:
        $a and $b
}

rule LinuxElknot
{
    meta:
	Author      = "@benkow_"
        Date        = "2013/12/24" 
        Description = "Strings inside"
        Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3099"

    strings:
        $a = "ZN8CUtility7DeCryptEPciPKci"
	$b = "ZN13CThreadAttack5StartEP11CCmdMessage"

    condition:
	all of them
}

rule LinuxMrBlack
{
    meta:
	Author      = "@benkow_"
        Date        = "2014/09/12" 
        Description = "Strings inside"
        Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "Mr.Black"
	$b = "VERS0NEX:%s|%d|%d|%s"
    condition:
        $a and $b
}

rule LinuxTsunami
{
    meta:
	
		Author      = "@benkow_"
		Date        = "2014/09/12" 
		Description = "Strings inside"
		Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "PRIVMSG %s :[STD]Hitting %s"
        $b = "NOTICE %s :TSUNAMI <target> <secs>"
        $c = "NOTICE %s :I'm having a problem resolving my host, someone will have to SPOOFS me manually."
    condition:
        $a or $b or $c
}

rule rootkit
{
	meta:
                author="xorseed"
                reference= "https://stuff.rop.io/"
	strings:
		$sys1 = "sys_write" nocase ascii wide	
		$sys2 = "sys_getdents" nocase ascii wide
		$sys3 = "sys_getdents64" nocase ascii wide
		$sys4 = "sys_getpgid" nocase ascii wide
		$sys5 = "sys_getsid" nocase ascii wide
		$sys6 = "sys_setpgid" nocase ascii wide
		$sys7 = "sys_kill" nocase ascii wide
		$sys8 = "sys_tgkill" nocase ascii wide
		$sys9 = "sys_tkill" nocase ascii wide
		$sys10 = "sys_sched_setscheduler" nocase ascii wide
		$sys11 = "sys_sched_setparam" nocase ascii wide
		$sys12 = "sys_sched_getscheduler" nocase ascii wide
		$sys13 = "sys_sched_getparam" nocase ascii wide
		$sys14 = "sys_sched_setaffinity" nocase ascii wide
		$sys15 = "sys_sched_getaffinity" nocase ascii wide
		$sys16 = "sys_sched_rr_get_interval" nocase ascii wide
		$sys17 = "sys_wait4" nocase ascii wide
		$sys18 = "sys_waitid" nocase ascii wide
		$sys19 = "sys_rt_tgsigqueueinfo" nocase ascii wide
		$sys20 = "sys_rt_sigqueueinfo" nocase ascii wide
		$sys21 = "sys_prlimit64" nocase ascii wide
		$sys22 = "sys_ptrace" nocase ascii wide
		$sys23 = "sys_migrate_pages" nocase ascii wide
		$sys24 = "sys_move_pages" nocase ascii wide
		$sys25 = "sys_get_robust_list" nocase ascii wide
		$sys26 = "sys_perf_event_open" nocase ascii wide
		$sys27 = "sys_uname" nocase ascii wide
		$sys28 = "sys_unlink" nocase ascii wide
		$sys29 = "sys_unlikat" nocase ascii wide
		$sys30 = "sys_rename" nocase ascii wide
		$sys31 = "sys_read" nocase ascii wide
		$sys32 = "kobject_del" nocase ascii wide
		$sys33 = "list_del_init" nocase ascii wide
		$sys34 = "inet_ioctl" nocase ascii wide
	condition:
		9 of them
}

rule exploit
{
        meta:
                author="xorseed"
                reference= "https://stuff.rop.io/"
	strings:
		$xpl1 = "set_fs_root" nocase ascii wide
		$xpl2 = "set_fs_pwd" nocase ascii wide
		$xpl3 = "__virt_addr_valid" nocase ascii wide
		$xpl4 = "init_task" nocase ascii wide
		$xpl5 = "init_fs" nocase ascii wide
		$xpl6 = "bad_file_ops" nocase ascii wide
		$xpl7 = "bad_file_aio_read" nocase ascii wide
		$xpl8 = "security_ops" nocase ascii wide
		$xpl9 = "default_security_ops" nocase ascii wide
		$xpl10 = "audit_enabled" nocase ascii wide
		$xpl11 = "commit_creds" nocase ascii wide
		$xpl12 = "prepare_kernel_cred" nocase ascii wide
		$xpl13 = "ptmx_fops" nocase ascii wide
		$xpl14 = "node_states" nocase ascii wide
	condition:
		7 of them
}

/* Yara rule to detect Linux/Httpsd generic
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
    and  open to any user or organization, as long as you use it under this license.
*/

private rule is__LinuxHttpsdStrings {

    meta:
	description = "Strings of ELF Linux/Httpsd (backdoor, downloader, remote command execution)"
	ref1 = "https://imgur.com/a/8mFGk"
	ref2 = "https://otx.alienvault.com/pulse/5a49115f93199b171b90a212"
	ref3 = "https://misppriv.circl.lu/events/view/9952"
	author = "unixfreaxjp"
	org = "MalwareMustDie"
	date = "2018-01-02"
	sha256 = "dd1266561fe7fcd54d1eb17efbbb6babaa9c1f44b36cef6e06052e22ce275ccd"
	sha256 = "1b3718698fae20b63fbe6ab32411a02b0b08625f95014e03301b49afaee9d559"
		
	strings:
		$st01 = "k.conectionapis.com" fullword nocase wide ascii
		$st02 = "key=%s&host_name=%s&cpu_count=%d&os_type=%s&core_count=%s" fullword nocase wide ascii
		$st03 = "id=%d&result=%s" fullword nocase wide ascii
		$st04 = "rtime" fullword nocase wide ascii
		$st05 = "down" fullword nocase wide ascii
		$st06 = "cmd" fullword nocase wide ascii
		$st07 = "0 */6 * * * root" fullword nocase wide ascii
		$st08 = "/etc/cron.d/httpsd" fullword nocase wide ascii
		$st09 = "cat /proc/cpuinfo |grep processor|wc -l" fullword nocase wide ascii
		$st10 = "k.conectionapis.com" fullword nocase wide ascii
		$st11 = "/api" fullword nocase wide ascii
		$st12 = "/tmp/.httpslog" fullword nocase wide ascii
		$st13 = "/bin/.httpsd" fullword nocase wide ascii
		$st14 = "/tmp/.httpsd" fullword nocase wide ascii
		$st15 = "/tmp/.httpspid" fullword nocase wide ascii
		$st16 = "/tmp/.httpskey" fullword nocase wide ascii

	condition:
		all of them
}

rule Linux_Httpsd_malware_ARM {
  
	meta:
		description = "Detects Linux/Httpsd ARMv5"
		date = "2017-12-31"

	strings:
		$hexsts01 = { f0 4f 2d e9 1e db 4d e2 ec d0 4d e2 01 40 a0 e1 } // main
		$hexsts02 = { f0 45 2d e9 0b db 4d e2 04 d0 4d e2 3c 01 9f e5 } // self-rclocal
		$hexsts03 = { f0 45 2d e9 01 db 4d e2 04 d0 4d e2 bc 01 9f e5 } // copy-self

	condition:
		all of them
        	and uint32(0) == 0x464c457f
		and is__LinuxHttpsdStrings
		and filesize < 200KB 
}

rule Linux_Httpsd_malware_i686 {

	meta:
		description = "Detects ELF Linux/Httpsd i686"
		date = "2018-01-02"

	
	strings:
		$hexsts01 = { 8d 4c 24 04 83 e4 f0 ff 71 fc 55 89 e5 57 56 53 } // main
		$hexsts02 = { 55 89 e5 57 56 53 81 ec 14 2c 00 00 68 7a 83 05 } // self-rclocal
		$hexsts03 = { 55 89 e5 57 56 53 81 ec 10 04 00 00 68 00 04 00 } // copy-self

	condition:
		all of them
        	and uint32(0) == 0x464c457f
		and is__LinuxHttpsdStrings
		and filesize < 200KB 
}
/* Yara rule to detect Mirai Okiru generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/


rule Mirai_Okiru {
	meta:
		description = "Detects Mirai Okiru MALW"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
		date = "2018-01-05"

	strings:
		$hexsts01 = { 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }
		$hexsts02 = { 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }
		// noted some Okiru variant doesnt have below function, uncomment to seek specific x86 bins
    // $st07 = "iptables -F\n" fullword nocase wide ascii
    
	condition:
    		all of them
		and uint32(0) == 0x464c457f
		and filesize < 100KB 
}
/* Yara rule to detect Mirai Satori generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/

private rule is__Mirai_Satori_gen {
	meta:
		description = "Detects Mirai Satori_gen"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
		date = "2018-01-05"

	strings:
		$st08 = "tftp -r satori" fullword nocase wide ascii
		$st09 = "/bins/satori" fullword nocase wide ascii
		$st10 = "satori" fullword nocase wide ascii
		$st11 = "SATORI" fullword nocase wide ascii

	condition:
		2 of them
}

rule Mirai_Satori {
	meta:
		description = "Detects Mirai Satori MALW"
		date = "2018-01-09"

	strings:
		$hexsts01 = { 63 71 75 ?? 62 6B 77 62 75 }
		$hexsts02 = { 53 54 68 72 75 64 62 }
		$hexsts03 = { 28 63 62 71 28 70 66 73 64 6F 63 68 60 } 

	condition:
		all of them
		and uint32(0) == 0x464c457f
		and is__Mirai_Satori_gen
		and filesize < 100KB 
}
/* Yara rule to detect ELF Linux malware Rebirth Vulcan (Torlus next-gen) generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/

private rule is__str_Rebirth_gen3 {
	meta:
		description = "Generic detection for Vulcan branch Rebirth or Katrina from Torlus nextgen"
		reference = "https://imgur.com/a/SSKmu"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7rprnx/vulcan_aka_linuxrebirth_or_katrina_variant_of/"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-21"
	strings:
        	$str01 = "/usr/bin/python" fullword nocase wide ascii
        	$str02 = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" fullword nocase wide ascii
        	$str03 = "Telnet Range %d->%d" fullword nocase wide ascii
        	$str04 = "Mirai Range %d->%d" fullword nocase wide ascii
        	$str05 = "[Updating] [%s:%s]" fullword nocase wide ascii
        	$str06 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*" fullword nocase wide ascii
		$str07 = "\x1B[96m[DEVICE] \x1B[97mConnected" fullword nocase wide ascii
	condition:
        	4 of them
}

private rule is__hex_Rebirth_gen3 {
	meta:
		author = "unixfreaxjp"
		date = "2018-01-21"
	strings:
		$hex01 = { 0D C0 A0 E1 00 D8 2D E9 }
		$hex02 = { 3C 1C 00 06 27 9C 97 98 }
		$hex03 = { 94 21 EF 80 7C 08 02 A6 }
		$hex04 = { E6 2F 22 4F 76 91 18 3F }
		$hex05 = { 06 00 1C 3C 20 98 9C 27 }
		$hex06 = { 55 89 E5 81 EC ?? 10 00 }
		$hex07 = { 55 48 89 E5 48 81 EC 90 }
		$hex08 = { 6F 67 69 6E 00 }
	condition:
        	2 of them 
}

private rule is__bot_Rebirth_gen3 {
	meta:
		author = "unixfreaxjp"
		date = "2018-01-21"
	strings:
        	$bot01 = "MIRAITEST" fullword nocase wide ascii
        	$bot02 = "TELNETTEST" fullword nocase wide ascii
        	$bot03 = "UPDATE" fullword nocase wide ascii
        	$bot04 = "PHONE" fullword nocase wide ascii
        	$bot05 = "RANGE" fullword nocase wide ascii
		$bot06 = "KILLATTK" fullword nocase wide ascii
		$bot07 = "STD" fullword nocase wide ascii
        	$bot08 = "BCM" fullword nocase wide ascii
		$bot09 = "NETIS" fullword nocase wide ascii
		$bot10 = "FASTLOAD" fullword nocase wide ascii
	condition:
        	6 of them
}

rule MALW_Rebirth_Vulcan_ELF {
	meta:
		description = "Detects Rebirth Vulcan variant a torlus NextGen MALW"
		description = "Just adjust or omit below two strings for next version they code :) @unixfreaxjp"
		date = "2018-01-21"
	strings:
                $spec01 = "vulcan.sh" fullword nocase wide ascii
		$spec02 = "Vulcan" fullword nocase wide ascii
	condition:
                all of them
		and uint32(0) == 0x464c457f
		and is__str_Rebirth_gen3
		and is__hex_Rebirth_gen3
		and is__bot_Rebirth_gen3
		and filesize < 300KB 
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule ELF_Linux_Torte : Linux ELF

{
    meta:
		author = "@mmorenog,@yararules"
		description = "Detects ELF Linux/Torte infection"
		ref = "http://blog.malwaremustdie.org/2016/01/mmd-0050-2016-incident-report-elf.html"
		hash1 = "1faf27f6b8e8a9cadb611f668a01cf73"
		hash2 = "cb0477445fef9c5f1a5b6689bbfb941e"

    strings:
        $s0 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.6)"
        $s1 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.7.6)"
        $s2 = "?sessd="
        $s3 = "&sessc="
        $s4 = "&sessk="
        $s5 = "3a08fe7b8c4da6ed09f21c3ef97efce2"
        $s6 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s7 = "_ZN11CThreadPool10getBatchesERSt6vectorISt4pairISsiESaIS2_EE"
        $s8 = "_ZNSs4_Rep10_M_destroyERKSaIcE@@GLIBCXX_3.4"
        $s9 = "_ZNSt6vectorImSaImEE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPmS1_EERKm"
        $s10 = "_ZNSt6vectorISt4pairISsiESaIS1_EE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPS1_S3_EERKS1_"
        $s11 = "_ZSt20__throw_out_of_rangePKc@@GLIBCXX_3.4"
        
        condition:
        uint32(0) == 0x464c457f and all of ($s*)
}


rule ELF_Linux_Torte_domains {
	meta:
		author = "@mmorenog,@yararules"
		description = "Detects ELF Linux/Torte infection"
		ref1 = "http://blog.malwaremustdie.org/2016/01/mmd-0050-2016-incident-report-elf.html"
	strings:
		$1 = "pages.touchpadz.com" ascii wide nocase
		$2 = "bat.touchpadz.com" ascii wide nocase
		$3 = "stat.touchpadz.com" ascii wide nocase
		$4 = "sk2.touchpadz.com" ascii wide nocase

	condition:
		any of them
}
rule Erebus: ransom
{
	meta:
		description = "Erebus Ransomware"
		author = "Joan Soriano / @joanbtl"
		date = "2017-06-23"
		version = "1.0"
		MD5 = "27d857e12b9be5d43f935b8cc86eaabf"
		SHA256 = "0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f"
		ref1 = "http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/"
	strings:
		$a = "/{5f58d6f0-bb9c-46e2-a4da-8ebc746f24a5}//log.log"
		$b = "EREBUS IS BEST."
	condition:
		all of them
}
