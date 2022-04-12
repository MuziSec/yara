rule Arkei {
    meta:
        author = "muzi"
        date = "2022-04-09"
        description = "Detects Arkei Stealer."
        hash = "fbc4983f6003ffbcbcfac4cae47c944a"


    strings:
        $decrypt = {
                     A3 ?? ?? ?? ?? // [decrypted]
                     6A ?? // Push Len Ciphertext
                     68 ?? ?? ?? ?? // Push Ciphertext
                     68 ?? ?? ?? ?? // Push Key
                     E8 ?? ?? ?? ?? // Call Decrypt 
                     83 C4 ?? // add esp,  
        }
 
        $s1 = "JohnDoe"
        $s2 = "KardiaChain"
        $s3 = "Tag:"
        $s4 = "Is Laptop:"
        $s5 = "Grabber\\%s.zip"
        $s6 = "passphrase.json"
        $s7 = "Autofill\\%s_%s.txt"
        $s8 = "Cookies\\%s_%s.txt"
        $s9 = "History\\%s_%s.txt"
        $s10 = "logins.json"
        $s11 = "/c timeout /t 5 & del /f /q \"%s\" & exit"
        $s12 = "*allet*.dat"
        $s13 = "%DRIVE_REMOVABLE%"
        $s14 = "%DRIVE_FIXED%"
        $s15 = "CC\\%s_%s.txt"
        $s16 = "\"os_crypt\":{\"encrypted_key\":\""
        $s17 = "SELECT host, isHttpOnly, path, isSecure, expiry, name, value FROM moz_cookies"
        $s18 = "SELECT fieldname, value FROM moz_formhistory"
        $s19 = "Cookies\\%s_%s.txt"
        $s20 = "screenshot.jpg"
        $s21 = "HAL9TH"


    condition:
        uint16be(0) == 0x4D5A and
        #decrypt > 200 or 
        12 of them
}

 
