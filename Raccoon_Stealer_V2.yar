rule Raccoon_Stealer_V2: raccoon_stealer_v2
{
    meta:
	author = "muzi"
	date = "2022-07-22"
        description = "Detects Raccoon Stealer V2 (unpacked)"
        hash = "022432f770bf0e7c5260100fcde2ec7c49f68716751fd7d8b9e113bf06167e03"

    strings:
        $s1 = "Profile %d" wide
        $s2 = "Login Data" wide
        $s3 = "0Network\\Cookies" wide
        $s4 = "Web Data" wide
        $s5 = "*.lnk" wide
        $s6 = "\\ffcookies.txt" wide
        $s7 = "	%s %s" wide
        $s8 = "wallet.dat" wide
        $s9 = "S-1-5-18" wide // malware checks if running as system

    condition:
        6 of them

}
