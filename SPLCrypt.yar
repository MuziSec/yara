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
        $constant = { 47 48 59 55 67 61 66 67 36 35 32 74 79 33 79 75 64 67 75 61 73 69 75 68 75 66 31 75 79 32 31 31 }

        /*
                                   LAB_18000c2b0                                   XREF[1]:     18000c2c9(j)  
        18000c2b0 0f b6 0a        MOVZX      param_1,byte ptr [RDX]
        18000c2b3 c1 c8 0d        ROR        EAX,0xd
        18000c2b6 80 f9 61        CMP        param_1,0x61
        18000c2b9 72 04           JC         LAB_18000c2bf
        18000c2bb 48 83 c0 e0     ADD        RAX,-0x20
        */

        $rord = {
                  0f b6 ?? [0-12]
                  C1 (C8|CA|CB|CD|CE|CF) 0d [0-8]
                  80 ?? 61 [0-8]
                  (E2|EB|72|74|75|7C) ?? 
        }
        
        /*
        74B25197 | 0F84 BC000000            | je dfhn.74B25259                        |
	74B2519D | 50                       | push eax                                |
	74B2519E | FF55 F4                  | call dword ptr ss:[ebp-C]               | CreateSection
	74B251A1 | 3AFF                     | cmp bh,bh                               |
	74B251A3 | 0F84 D3000000            | je dfhn.74B2527C                        |
	74B251A9 | 8945 FC                  | mov dword ptr ss:[ebp-4],eax            |
	74B251AC | FF75 F8                  | push dword ptr ss:[ebp-8]               |
	74B251AF | EB 13                    | jmp dfhn.74B251C4                       |
	74B251B1 | C9                       | leave                                   |
	74B251B2 | C3                       | ret                                     |
	74B251B3 | 50                       | push eax                                |
	74B251B4 | 6A 00                    | push 0                                  |
	74B251B6 | E9 A8000000              | jmp dfhn.74B25263                       |
	74B251BB | 6A 00                    | push 0                                  | SectionPageProtection
	74B251BD | 68 00000008              | push 8000000                            | SEC_COMMIT
	74B251C2 | EB 33                    | jmp dfhn.74B251F7                       |
	74B251C4 | FF55 E8                  | call dword ptr ss:[ebp-18]              |
	74B251C7 | 8B45 FC                  | mov eax,dword ptr ss:[ebp-4]            |
	74B251CA | EB E5                    | jmp dfhn.74B251B1                       |
	74B251CC | 8B45 10                  | mov eax,dword ptr ss:[ebp+10]           |
	74B251CF | 8945 E4                  | mov dword ptr ss:[ebp-1C],eax           |
	74B251D2 | EB E7                    | jmp dfhn.74B251BB                       |
	74B251D4 | 8365 F0 00               | and dword ptr ss:[ebp-10],0             |
	74B251D8 | 8365 FC 00               | and dword ptr ss:[ebp-4],0              |
	74B251DC | EB 0E                    | jmp dfhn.74B251EC                       |
	74B251DE | FF75 08                  | push dword ptr ss:[ebp+8]               |
	74B251E1 | 6A FF                    | push FFFFFFFF                           | Handle = Self
	74B251E3 | EB 2A                    | jmp dfhn.74B2520F                       |
	74B251E5 | FF75 14                  | push dword ptr ss:[ebp+14]              |
	74B251E8 | 6A 00                    | push 0                                  |
	74B251EA | EB 56                    | jmp dfhn.74B25242                       |
	74B251EC | 8B45 0C                  | mov eax,dword ptr ss:[ebp+C]            |
	74B251EF | 8945 E0                  | mov dword ptr ss:[ebp-20],eax           |
	74B251F2 | 66:3BC0                  | cmp ax,ax                               |
	74B251F5 | 74 D5                    | je dfhn.74B251CC                        |
	74B251F7 | FF75 14                  | push dword ptr ss:[ebp+14]              | ObjectAttributes
	74B251FA | 8D45 E0                  | lea eax,dword ptr ss:[ebp-20]           |
	74B251FD | 3AED                     | cmp ch,ch                               |
	74B251FF | 0F84 8C000000            | je dfhn.74B25291                        |
	74B25205 | 68 1F000F00              | push F001F                              | DesiredAccess = SECTION_ALL_ACCESS
	74B2520A | 8D45 F8                  | lea eax,dword ptr ss:[ebp-8]            | Handle
	74B2520D | EB 8E                    | jmp <dfhn.Handle>                       |
	74B2520F | FF75 F8                  | push dword ptr ss:[ebp-8]               |
	74B25212 | FF55 EC                  | call dword ptr ss:[ebp-14]              |
        */

        $section_mapping = {
                             6A 00
                             68 00 00 00 08 [0-50]
                             6A FF [0-50]
                             68 1F 00 0F 00
        }

        $add_ecx_section_mapping = {B9 ?? ?? ?? ?? 81 C1 ?? ?? ?? ??}
        $sub_ecx_section_mapping = {B9 ?? ?? ?? ?? 81 E9 ?? ?? ?? ??}

        $add_edx_section_mapping = {BA ?? ?? ?? ?? 81 C2 ?? ?? ?? ??}
        $sub_edx_section_mapping = {BA ?? ?? ?? ?? 81 EA ?? ?? ?? ??}

    condition:
        $rord or
        $section_mapping or
        $constant or 
        for any of ($add*):
        (
            (uint32(@+1) + uint32(@+7)) == 0x000F001F
        ) or
        for any of ($sub*):
        (
            (uint32(@+1) + uint32(@+7)) == 0x000F001F
        ) or
        #match_1_shr > 1 and #match_2_shl_13 > 1 and
        for any i in (0..#match_1_shr):
            ($match_2_shl_13 in (@match_1_shr[i]..@match_1_shr[i]+200))
        
}
