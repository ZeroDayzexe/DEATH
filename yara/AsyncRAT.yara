import "pe"
rule MAL_WIN_AsyncRAT_Stealer_PE
{
    meta:
        description = "This rule detects a remote access trojan known as AsyncRAT disguising itself as a filename called Stub.exe"
        author = "Kaylil Davis"
        date = "2/2/2025"
        reference = "https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/asyncrat"
        hash = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
    strings:
        $s1 = "Select * from AntivirusProduct" wide // Gathering information about antivirus
        $s2 = "/c taskkill.exe /im chrome.exe /f" wide // Forcefully terminate instances of google chrome that are running
        $s3 = "AVRemoval.Class1" wide // function that likely attempts to remove any antivirus
        $s4 = "isDebuggerPresent"
        $s5 = "ABRIL.exe"
        $s6 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide// forces the creation of a scheduled task with elevated privs
        $s7 = "LimeLogger" // Appears to be a keylogger: https://github.com/NYAN-x-CAT/LimeLogger
        $s8 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide // Apears to be an attempt to obfuscate activity
        $s9 = "\\extensions\\webextension@metamask.io.xpi" wide
        $s10 = "\\Log.tmp" wide

    condition:
        not pe.is_signed and
        pe.version_info["OriginalFilename"] == "Stub.exe" and
        filesize < 180KB and 
        9 of ($s*)
}