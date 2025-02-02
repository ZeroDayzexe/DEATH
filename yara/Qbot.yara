import "pe"
rule MAL_WIN_Qbot_Trojan_PE
{
    meta:
        description = "Detects DLLs associated with Qbot malware"
        author = "Kaylil Davis"
        date = "2/1/2025"
        reference = "https://redcanary.com/threat-detection-report/threats/qbot/"
        hash = "6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59" //SHA256
    strings:
        $s1 = "WinSta0" // Interactive window station
        $s2 = "GetClipboardData"
        $s3 = "TrackMouseEvent" //Possibly tracking activity when interacting with different windiws
        $s4 = "Tdk_screen_broadcast_client_message" 
        $s5 = "Tdk_screen_get_root_window"
        $s6 = "gdk_screen_get_toplevel_windows"
        $s7 = "bugzilla.gnome.org"
        $s8 = "MapVirtualKeyA"
        $s9 = "Tdk_spawn_command_line_on_screen"
    condition:
        all of ($s*) and
        pe.characteristics & pe.DLL and
        not pe.is_signed and
        pe.imports("USER32.dll","MessageBeep") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        filesize < 1000KB        
}