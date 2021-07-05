rule CryptOne_Packer  {
    
meta:
        author = "muzi"
        date = "06/30/2021"
        description = "Detects CryptOne packer. Typically used to crypt Cobalt Strike, Gozi ISFB, Zloader and Smokeloader. It uses multiple busy loops to throw off static analysis and also performs a number of system calls to simulate Sleep. The encrypted shellcode/exe is stored as a resource."
        references = "https://www.deepinstinct.com/2021/05/26/deep-dive-packing-software-cryptone/"

    strings:
        /*
          Packer makes cmp dword to 0 several times for no reason, then jumps
	  0044D417 | 833D 88384500 00         | cmp dword ptr ds:[453888],0             |
	  0044D41E | 74 05                    | je 5h99akse5er.44D425                   |
	  0044D420 | E8 ABFFFFFF              | call 5h99akse5er.44D3D0                 |
	  0044D425 | 833D 88384500 00         | cmp dword ptr ds:[453888],0             |
	  0044D42C | 74 05                    | je 5h99akse5er.44D433                   |
	  0044D42E | E8 2DFEFFFF              | call 5h99akse5er.44D260                 |
	  0044D433 | 833D 88384500 00         | cmp dword ptr ds:[453888],0             |
	  0044D43A | 74 05                    | je 5h99akse5er.44D441                   |
	  0044D43C | E8 8FFFFFFF              | call 5h99akse5er.44D3D0                 |
	  0044D441 | 833D 88384500 00         | cmp dword ptr ds:[453888],0             |
	  0044D448 | 74 05                    | je 5h99akse5er.44D44F                   |
	  0044D44A | E8 11FEFFFF              | call 5h99akse5er.44D260                 |
	  0044D44F | 833D 88384500 00         | cmp dword ptr ds:[453888],0             |
	  0044D456 | 74 05                    | je 5h99akse5er.44D45D                   |
	  0044D458 | E8 03FEFFFF              | call 5h99akse5er.44D260                 |
	  0044D45D | 833D 88384500 00         | cmp dword ptr ds:[453888],0             |
	  0044D464 | 74 0F                    | je 5h99akse5er.44D475                   |
        */

        $worthless_cmp = {
                            83 3D ?? ?? ?? 00 00                            [0-8]       // cmp dword <dword ptr> 0
                            74 ??                                           [0-8]       // je <address>
                            (E8|FF) ?? ?? ?? ??                             [0-8]       // call <function>
                            83 3D ?? ?? ?? 00 00                                        // cmp dword <dword ptr> 0
                          }

        /*
          0044d1c4 ff 15 4c        CALL       dword ptr [->KERNEL32.DLL::GetLastError]
                   26 45 00
          0044d1ca 83 f8 06        CMP        EAX,0x6
          0044d1cd 74 04           JZ         LAB_0044d1d3
          0044d1cf 33 c0           XOR        EAX,EAX
                               LAB_0044d1d3                                    XREF[1]:     0044d1cd(j)
          0044d1d3 68 bc 38        PUSH       DAT_004538bc
                   45 00
          0044d1d8 8b 45 f8        MOV        EAX,dword ptr [EBP + local_c]
          0044d1db 50              PUSH       EAX=>DAT_004521b4                                = 35h
          0044d1dc 8b 0d 34        MOV        ECX,dword ptr [DAT_00452134]                     = 80000020h
                   21 45 00
          0044d1e2 83 e9 20        SUB        ECX,0x20
          0044d1e5 51              PUSH       ECX
          0044d1e6 ff 15 44        CALL       dword ptr [->ADVAPI32.DLL::RegOpenKeyA]
                   29 45 00
          0044d1ec 89 45 fc        MOV        dword ptr [EBP + local_8],EAX
          0044d1ef 83 7d fc 00     CMP        dword ptr [EBP + local_8],0x0
          0044d1f3 74 0b           JZ         LAB_0044d200
                               LAB_0044d1f5                                    XREF[1]:     0044d1fe(j)
          0044d1f5 ba 01 00        MOV        EDX,0x1
                   00 00
          0044d1fa 85 d2           TEST       EDX,EDX
          0044d1fc 74 02           JZ         LAB_0044d200
          0044d1fe eb f5           JMP        LAB_0044d1f5
        */

        $reg_key_check = {
                     (FF|E8) ?? ?? ?? ?? ??                                              // CALL dword ptr [->KERNEL32.DLL::GetLastError]
                     (83|93|A3|B3|C3|D3) (F8|F9|FA|FB|FC|FD|FE|FF) 06 [0-64]             // CMP <reg> 6
                     68 ?? ?? ?? ?? [0-8]                                                // PUSH data
                     (88|89|8A|8B|8C) (45|4D|55|5D|6D|75|7D) (F?|E?|D?|C?|B?|A?) [0-8]   // MOV <reg>, [ebp + offset]
                     5? [0-8]                                                            // PUSH <reg>
                     (88|89|8A|8B|8C) (0d|15|1d|25|2d|35|3d) ?? ?? ?? ?? [0-24]          // MOV <reg> dword
                     ff ?? ?? ?? ?? ?? [0-8]                                             // CALL dword ptr [->ADVAPI32.DLL::RegOpenKeyA]
                     (88|89|8A|8B|8C) 45 (F8|F9|FA|FB|FC|FD|FE|FF)          [0-8]        // MOV [EBP + local_8], EAX
                     83 (78|79|7A|7B|7D|7E|7F) (F8|F9|FA|FB|FC|FD|FE|FF) 00 [0-8]        // CMP dword ptr [EBP + offset],0x0
                     (E2|EB|72|74|75|7C) ?? [0-64]                                       // Conditional JMP (Heading for Inf Loop)
                     (B8|B9|BA|BB|BD|BE|BF) 01 00 00 00 [0-8]                            // MOV <reg>, 0x1
                     (84|85) (D0|D1|D2|D3|D5|D6|D7) [0-8]                                // TEST <reg>,<reg>
                     (E2|EB|72|74|75|7C) ?? [0-8]                                        // Loop/Conditional JMP
                     (E2|EB|72|74|75|7C) ??                                              // Loop/Conditional JMP
                   }

       /*
        00401e6f 81 ea ad        SUB        EDX,0xcad
                 0c 00 00
        00401e75 52              PUSH       EDX
        00401e76 ff 15 5c        CALL       dword ptr [DAT_004eb45c]
                 b4 4e 00
        00401e7c 89 45 fc        MOV        dword ptr [EBP + local_8],EAX
        00401e7f 83 7d fc 00     CMP        dword ptr [EBP + local_8],0x0
        00401e83 74 0b           JZ         LAB_00401e90
                             LAB_00401e85                                    XREF[1]:     00401e8e(j)
        00401e85 b8 01 00        MOV        EAX,0x1
                 00 00
        00401e8a 85 c0           TEST       EAX,EAX
        00401e8c 74 02           JZ         LAB_00401e90
        00401e8e eb f5           JMP        LAB_00401e85
                             LAB_00401e90                                    XREF[2]:     00401e83(j), 00401e8c(j)
        00401e90 e8 0b f4        CALL       FUN_004012a0                                     undefined * FUN_004012a0(void)
                 ff ff
        00401e95 a3 78 a1        MOV        [DAT_004ea178],EAX                               = 00000042h
                 4e 00
        00401e9a 8b e5           MOV        ESP,EBP
        00401e9c 5d              POP        EBP
        00401e9d c3              RET
       */

       $reg_key_check_2 = {
                            (80|81|82|83) ?? ?? ?? ?? ?? [0-8]                                            // SUB <reg>, <value>
                            (50|51|52|53|55|56|57) [0-8]                                                  // PUSH <reg>
                            ff ?? ?? ?? ?? ?? [0-8]                                                       // CALL dword ptr [->ADVAPI32.DLL::RegOpenKeyA]
                            (88|89|8A|8B|8C) 45 (F8|F9|FA|FB|FC|FD|FE|FF)          [0-8]                  // MOV [EBP + local_8], EAX
                            (83|93|A3|B3|C3|D3) (78|79|7A|7B|7D|7E|7F) (F8|F9|FA|FB|FC|FD|FE|FF) 00 [0-8] // CMP dword ptr [EBP + local_8], 0x0
                            (E2|EB|72|74|75|7C) ?? [0-8]                                                  // Conditional JMP
                            (B8|B9|BA|BB|BD|BE|BF) 01 00 00 00 [0-8]                                      // MOV <reg>, 0x1
                            (84|85) (C0|C1|C2|C3|C4|C5|C6|C7) [0-8]                                       // TEST <reg>,<reg>
                            (E2|EB|72|74|75|7C) ?? [0-8]                                                  // Conditional JMP
                            (E2|EB|72|74|75|7C) ??                                                        // Inf Loop JMP
                          }

       /*
        00402d35 50              PUSH       EAX=>u_aaaerfacE\{b196b287-bab4-101a-b6_00527800 = u"aaaerfacE\\{b196b287-bab4-10
        00402d36 8b 0d fc        MOV        ECX,dword ptr [DAT_005277fc]                     = 80000002h
                 77 52 00
        00402d3c 83 e9 02        SUB        ECX,0x2
        00402d3f 51              PUSH       ECX
        00402d40 ff 55 f8        CALL       dword ptr [EBP + local_c]
        00402d43 89 45 fc        MOV        dword ptr [EBP + local_8],EAX
        00402d46 83 7d fc 00     CMP        dword ptr [EBP + local_8],0x0
        00402d4a 74 0b           JZ         LAB_00402d57
                             LAB_00402d4c                                    XREF[1]:     00402d55(j)
        00402d4c ba 01 00        MOV        EDX,0x1
                 00 00
        00402d51 85 d2           TEST       EDX,EDX
        00402d53 74 02           JZ         LAB_00402d57
        00402d55 eb f5           JMP        LAB_00402d4c
       */

       $reg_key_check_3 = {

                            (50|51|52|53|55|56|57) [0-8]                                                  // PUSH <reg>
                            (88|89|8A|8B|8C) (0d|15|1d|25|2d|35|3d) ?? ?? ?? ?? [0-8]                     // MOV <reg>, dword
                            (80|81|82|83) ?? ??  [0-8]                                                    // SUB <reg>, <value>
                            (50|51|52|53|55|56|57) [0-8]                                                  // PUSH <reg>
                            ff ?? ??  [0-8]                                                               // CALL dword ptr [->ADVAPI32.DLL::RegOpenKeyA]
                            (88|89|8A|8B|8C) 45 (F8|F9|FA|FB|FC|FD|FE|FF)          [0-8]                  // MOV [EBP + local_8], EAX
                            (83|93|A3|B3|C3|D3) (78|79|7A|7B|7D|7E|7F) (F8|F9|FA|FB|FC|FD|FE|FF) 00 [0-8] // CMP dword ptr [EBP + local_8], 0x0
                            (E2|EB|72|74|75|7C) ?? [0-8]                                                  // Conditional JMP
                            (B8|B9|BA|BB|BD|BE|BF) 01 00 00 00 [0-8]                                      // MOV <reg>, 0x1
                            (84|85) (D0|D1|D2|D3|D4|D5|D6|D7) [0-8]                                       // TEST <reg>,<reg>
                            (E2|EB|72|74|75|7C) ?? [0-8]                                                  // Conditional JMP
                            (E2|EB|72|74|75|7C) ??                                                        // Inf Loop JMP

                          }

      /*
        Infinite Loop Check - Malware always checks for a certain reg key and if it doesn't exist, it will loop infinitely. This probably shouldn't ever exist in legitimate code.
      */

      $inf_loop_eax = {B8 01 00 00 00
                       85 C0
                       7? 0?
                       EB F?}

      $inf_loop_ecx = {B9 01 00 00 00
                       85 C9
                       7? 0?
                       EB F?}

      $inf_loop_edx = {BA 01 00 00 00
                       85 CA
                       7? 0?
                       EB F?}

      $inf_loop_ebx = {BB 01 00 00 00
                       85 CB
                       7? 0?
                       EB F?}

      $inf_loop_ebp = {BD 01 00 00 00
                       85 CD
                       7? 0?
                       EB F?}

      $inf_loop_esi = {BE 01 00 00 00
                       85 CE
                       7? 0?
                       EB F?}

      $inf_loop_edi = {BF 01 00 00 00
                       85 CF
                       7? 0?
                       EB F?}

    condition:

        (#worthless_cmp >= 3 and ($reg_key_check or $reg_key_check_2 or $reg_key_check_3)) or

        $reg_key_check_3 or

        any of ($inf_loop_*)

 

}
