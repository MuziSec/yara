rule Arkei {
    meta:
        author = "muzi"
        date = "2022-04-09"
        description = "Detects Arkei Stealer and also maybe Vidar/Mars variants"
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
 
        $decrypt2 = {
                      A3 ?? ?? ?? ??
                      68 ?? ?? ?? ??
                      E8 ?? ?? ?? ??
                      83 C4 ??
        }

    condition:
        uint16be(0) == 0x4D5A and
        1 of them
}

 
