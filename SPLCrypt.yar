rule SPLCrypt {

    meta:
        author = "muzi"
        description = "Identifies SPLCrypt, a crypter associated with Bazar."
        date = "01/16/22"

    strings:

        // Implementation of ROR(x, 0x0D)
        // (x << 0x13|x >> 0x0D) == ROR(x,0x0D)
        /*
        00007FFADADC4E37 | 8B0424                   | mov eax,dword ptr ss:[rsp]              | hash
	00007FFADADC4E3A | C1E8 0D                  | shr eax,D                               |
	00007FFADADC4E3D | 66:3BFF                  | cmp di,di                               |
	00007FFADADC4E40 | 74 4C                    | je splcrypt_bazar.7FFADADC4E8E          |
	*/
        $match_1_shr = {

                         (8B|8D) ?? 24 [0-8]                            // mov <reg>, dword ptr ss:[rsp] hash
                         C1 (E8|E9|EA|EB|ED|EE|EF) 0D [0-16]            // shr <reg>, D
                         (E2|EB|72|74|75|7C) ??                         // Conditional JMP
        }

        /*
        00007FFADADC4E85 | 48:634424 04             | movsxd rax,dword ptr ss:[rsp+4]         | i
	00007FFADADC4E8A | 3AFF                     | cmp bh,bh                               |
	00007FFADADC4E8C | 74 DE                    | je splcrypt_bazar.7FFADADC4E6C          |
	00007FFADADC4E8E | 8B0C24                   | mov ecx,dword ptr ss:[rsp]              |
	00007FFADADC4E91 | C1E1 13                  | shl ecx,13                              |
	00007FFADADC4E94 | E9 44FFFFFF              | jmp splcrypt_bazar.7FFADADC4DDD
	*/

        $match_2_shl_13 = {
                            (8B|8D) ?? 24 [0-8]
                            C1 (E0|E1|E2|E3|E5|E6|E7) 13
        }

    condition:
        for any i in (0..#match_1_shr):
            ($match_2_shl_13 in (@match_1_shr[i]..@match_1_shr[i]+200))

}
