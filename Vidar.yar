rule Vidar {
    meta:
        author = "muzi"
        date = "2022-04-09"
        description = "Detects Vidar Stealer."
        hash = "fbc4983f6003ffbcbcfac4cae47c944a"

    strings:
        $s1 = "files\\information.txt" ascii wide nocase
        $s2 = "files\\passwords.txt" ascii wide nocase
        $s3 = "files\\CC\\" ascii wide nocase
        $s4 = "files\\Autofill\\" ascii wide nocase
        $s5 = "files\\Cookies\\" ascii wide nocase
        $s6 = "files\\Downloads\\" ascii wide nocase
        $s7 = "files\\cookie_list.txt" ascii wide nocase
        $s8 = "ISP:" ascii wide nocase
        $s9 = "Coordinates:" ascii wide nocase
        $s10 = "SELECT action_url, username_value, password_value FROM logins" ascii wide nocase
        $s11 = "screenshot.jpg" ascii wide nocase
        $s12 = "/c taskkill /im" ascii wide nocase
        $s13 = "/f & erase" ascii wide nocase 
        $s14 = "Work Dir: %s" ascii wide nocase
        $s15 = "HWID: %s" ascii wide nocase
        $s16 = "%DRIVE_REMOVABLE%" ascii wide nocase
        $s17 = "%DRIVE_FIXED%" ascii wide nocase
        

    condition:
        uint16be(0) == 0x4D5A and
        10 of them
 
}
