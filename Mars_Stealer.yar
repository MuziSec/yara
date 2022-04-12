rule Mars_Stealer {
    meta:
        author = "muzi"
        date = "2022-04-09"
        description = "Detects Mars Stealer."
        hash = "fbc4983f6003ffbcbcfac4cae47c944a"

    strings:

        $s1 = "Grabber.zip" ascii wide nocase
        $s2 = "pidgin.log" ascii wide nocase
        $s3 = "%s\\%sKeywords.log" ascii wide nocase
        $s4 = "%s\\%sDownloads.log" ascii wide nocase
        $s5 = "%s\\%sAutofill.log" ascii wide nocase
        $s6 = "%s\\%sCookies.log" ascii wide nocase
        $s7 = "%s\\%sPasswords.log" ascii wide nocase
        $s8 = "%s\\%sCreditcards.log" ascii wide nocase
        $s9 = "%s\\%sCreditcardsMasked.log" ascii wide nocase
        $s10 = "%s\\%sdomains.log" ascii wide nocase
        $s11 = "passwords.log" ascii wide nocase
        $s12 = "filezilla.log" ascii wide nocase
        $s13 = "about.log" ascii wide nocase
        $s14 = "TCM.log" ascii wide nocase
        $s15 = "TotalCommander.log" ascii wide nocase
        $s16 = "history.log" ascii wide nocase
        $s17 = "screen.jpeg" wide nocase
        $s18 = "gVault.log" ascii wide nocase
        $s19 = "wbrowsers_passwords.log" ascii wide nocase
        $s20 = "URL:%ls" ascii wide nocase
        $s21 = "login:%ls" ascii wide nocase
        $s22 = "password:%ls" ascii wide nocase
        $s23 = "soft:%ls" ascii wide nocase


    condition:
        uint16be(0) == 0x4D5A and
        12 of them
} 
