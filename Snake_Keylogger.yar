rule Snake_Keylogger {

    meta:
        author = "muzi"
        date = "2021-08-20"
        description = "Detects Snake Keylogger (unpacked)"
        hashes = "96a6df07b7d331cd6fb9f97e7d3f2162e56f03b7f2b7cdad58193ac1d778e025"

    strings:
        $s1 = "TheSMTPEmail" ascii wide nocase
        $s2 = "TheSMTPPSWD" ascii wide nocase
        $s3 = "TheSMTPServer" ascii wide nocase
        $s4 = "TheSMTPReciver" ascii wide nocase
        $s5 = "TheFTPUsername" ascii wide nocase
        $s6 = "TheFTPPSWD" ascii wide nocase
        $s7 = "TheTelegramToken" ascii wide nocase
        $s8 = "TheTelegramID" ascii wide nocase
        $s9 = "loccle" ascii wide nocase
        $s10 = "get_KPPlogS" ascii wide nocase
        $s11 = "get_Scrlogtimerrr" ascii wide nocase
        $s12 = "UploadsKeyboardHere" ascii wide nocase
        $s13 = "get_ProHfutimer" ascii wide nocase
        $s14 = "Chrome_Killer" ascii wide nocase
        $s15 = "PWUploader" ascii wide nocase
        $s16 = "TelSender" ascii wide nocase
        $s17 = "RamSizePC" ascii wide nocase
        $s18 = "ClipboardSender" ascii wide nocase
        $s19 = "ScreenshotSender" ascii wide nocase
        $s20 = "StartKeylogger" ascii wide nocase
        $s21 = "TheStoragePWSenderTimer" ascii wide nocase
        $s22 = "TheStoragePWSender" ascii wide nocase
        $s23 = "TheHardDiskSpace2" ascii wide nocase
        $s24 = "registryValueKind_0" ascii wide nocase
        $s25 = "KeyLoggerEventArgsEventHandler" ascii wide nocase
        $s26 = "decryptOutlookPassword" ascii wide nocase
        $s27 = "TheWiFisOutput" ascii wide nocase
        $s28 = "wifipassword_single" ascii wide nocase
        $s29 = "WindowsProductKey_Orginal" ascii wide nocase
        $s30 = "TheWiFi_Orginal" ascii wide nocase
        $s31 = "OiCuntJollyGoodDayYeHavin" ascii wide nocase
        $s32 = "de4fuckyou" ascii wide nocase

    condition:
        uint16be(0) == 0x4D5A and
        8 of ($s*)
}
