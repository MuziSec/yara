rule XLoader_MacOS {

    meta:
        author = "muzi"
        date = "2021-08-20"
        description = "Detects XLoader for macOS"

    strings:
        /*
       100001bf8 48  8b  93       MOV        RDX ,qword ptr [RBX  + 0x8b8 ]                     lib
                 b8  08  00
                 00
       100001bff 48  8d  b3       LEA        RSI ,[RBX  + 0x9d0 ]                               target
                 d0  09  00
                 00
       100001c06 b9  02  00       MOV        ECX ,0x2                                         cfg_buffer_id
                 00  00
       100001c0b 41  b8  1a       MOV        R8D ,0x1a                                        func_num
                 00  00  00
       100001c11 48  89  df       MOV        RDI ,RBX                                         xl
       100001c14 e8  57  f3       CALL       ab_dlsym_get_func                                pthread_create
                 ff  ff
       100001c19 84  c0           TEST       AL ,AL
       100001c1b 0f  84  64       JZ         LAB_100001d85
                 01  00  00
       100001c21 48  8b  93       MOV        RDX ,qword ptr [RBX  + 0x8b8 ]                     lib
                 b8  08  00
                 00
       100001c28 48  8d  b3       LEA        RSI ,[RBX  + 0x918 ]                               target
                 18  09  00
                 00
       100001c2f b9  02  00       MOV        ECX ,0x2                                         cfg_buf_id
                 00  00
       100001c34 45  31  c0       XOR        R8D ,R8D                                         func_num
       100001c37 48  89  df       MOV        RDI ,RBX                                         xl
       100001c3a e8  31  f3       CALL       ab_dlsym_get_func                                exit
                 ff  ff

        */
       $dlsym_resolve_thread_create = {
                           (48|49|4c|4d) (8b|8d) ?? ?? ?? 00 00 [0-16]     // MOV RDX, qword ptr [RBX + 0xb8]
                           (48|49|4c|4d) 8d ?? ?? ?? 00 00 [0-16]          // LEA RSI, [RBX + 0x9d0]
                           (B8|B9|BA|BB|BD|BE|BF) 02 00 00 00 [0-16]       // MOV ECX, 0x2
                           (40|41|42|43|44|45|46|47) ?? 1a 00 00 00 [0-16] // MOV R8D, 0x1a
                           (48|49|4c|4d) 8? ?? [0-16]                      // MOV RDI, RBX
                           (E8|FF) ?? ?? ?? ??                             // Call func
       }
       $dlsym_resolve_exit = {
                           (48|49|4c|4d) (8b|8d) ?? ?? ?? 00 00 [0-16]     // MOV RDX, qword ptr [RBX + 0xb8]
                           (48|49|4c|4d) 8d ?? ?? ?? 00 00 [0-16]          // LEA RSI, [RBX + 0x918
                           (B8|B9|BA|BB|BD|BE|BF) 02 00 00 00 [0-32]       // MOV ECX, 0x2
                                                                           // XOR R8D, R8D (Could be xor, could be mov, etc.)
                           (48|49|4c|4d) 8? ?? [0-16]                      // MOV RDI, RBX
                           (E8|FF) ?? ?? ?? ??                             // Call func
       }

    condition:
        uint32be(0) == 0xCFFAEDFE and all of ($dlsym_*)
}
