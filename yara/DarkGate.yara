import "pe"
rule MAL_WIN_DarkGate_TROJ
{
    meta:
        description = "This rule detects the DarkGate Loader Trojan"
        author = "Kaylil Davis"
        date = "2-18-25"
        reference = "https://www.cybereason.com/blog/threat-alert-darkgate-loader"
        hash = "0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23"
    strings:
        $s1 = "-SilentCleanup.xml.txt" wide
        $s2 = "cdn3-adb1.online" wide //Low confidence string
        $s3 = "wldp.dll"
        $s4 = /C:\\Windows\\system32\\cryptbase\.SystemFunction[0-9]{3}/
        $s5 = "cryptbase_meow\\x64\\Release\\cryptbase.pdb"
        $s6 = "cryptbase.dll" //Malicious DLL
        $s7 = "WinHttpOpenRequest"
        $s8 = "Virtual Machine Detected" // Likely checking to see if being analyzed in a VM
    condition:
        pe.is_pe and not
        pe.is_signed and 
        filesize < 2000KB and
        7 of ($s*)
}