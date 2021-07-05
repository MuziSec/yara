rule Cobalt_Strike_Magic_MZ {
    meta:
        author = "muzi"
        date = "2021-07-04"

    condition:
        uint32be(0) == 0x4D5A5245 or uint32be(0) == 0x4D5A4152

}

