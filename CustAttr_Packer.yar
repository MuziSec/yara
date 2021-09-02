rule CustAttr_Packer {

    meta:
        author = "Jared Anderson"
        date = "2021-08-20"
        description = "Detects XLoader for macOS"
        hashes = ""

    strings:
        $s1 = "mscoree.dll" ascii wide nocase
        $x1 = "CutsAttr" ascii wide nocase
        $x2 = "SelectorX" ascii wide nocase
        $x3 = "CustAttr" ascii wide nocase
    condition:
        uint16be(0) == 0x4D5A and
        $s1 and
        1 of ($x*)
}
