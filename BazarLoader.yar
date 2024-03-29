rule BazarLoader {

    meta:
        author = "muzi"
        description = "Identifies BazarLoader."
        date = "02/18/22"

    strings:

        /*
       18000de19 c7  45  0b       MOV        dword ptr [RBP  + local_54 ],0x3d9ffcdb
                 db  fc  9f 
                 3d
       18000de20 c7  45  0f       MOV        dword ptr [RBP  + local_50 ],0x61c9eecc
                 cc  ee  c9 
                 61
       18000de27 c7  45  13       MOV        dword ptr [RBP  + local_4c ],0x3899b7ca
                 ca  b7  99 
                 38
       18000de2e c7  45  17       MOV        dword ptr [RBP  + local_48 ],0x5989f8d3
                 d3  f8  89 
                 59
       18000de35 8b  45  0b       MOV        EAX ,dword ptr [RBP  + local_54 ]
       18000de38 8a  45  07       MOV        AL ,byte ptr [RBP  + local_58 ]
       18000de3b 84  c0           TEST       AL ,AL
       18000de3d 75  19           JNZ        LAB_18000de58
       18000de3f 48  8b  cb       MOV        param_1 ,RBX
                             LAB_18000de42                                   XREF[1]:     18000de56 (j)   
       18000de42 8b  44  8d       MOV        EAX ,dword ptr [RBP  + param_1 *0x4  + local_50 ]
                 0b
       18000de46 35  a9  99       XOR        EAX ,0x59fb99a9
                 fb  59
        */


        $xor_hash = {
                      C7 4? [2-4] ?? ?? ?? ??
                      C7 4? [2-4] ?? ?? ?? ?? [10-30]
                      35
        }

        /*
       LAB_180012316                                   XREF[1]:     1800122ca (j)  
       180012316 40  88  7c       MOV        byte ptr [RSP  + local_1d0 ],DIL
                 24  78
       18001231b ba  e7  5f       MOV        param_2 ,0x1a705fe7
                 70  1a
       180012320 c7  44  24       MOV        dword ptr [RSP  + local_1cc ],0x72132994
                 7c  94  29
                 13  72
       180012328 c7  45  80       MOV        dword ptr [RBP  + local_1c8 ],0x34042c88
                 88  2c  04
                 34
       18001232f c7  45  84       MOV        dword ptr [RBP  + local_1c4 ],0x3a152782
                 82  27  15
                 3a
       180012336 89  55  88       MOV        dword ptr [RBP  + local_1c0 ],param_2
       180012339 8b  44  24       MOV        EAX ,dword ptr [RSP  + local_1cc ]
                 7c
       18001233d 8a  44  24       MOV        AL ,byte ptr [RSP  + local_1d0 ]
                 78
       180012341 84  c0           TEST       AL ,AL
       180012343 75  16           JNZ        LAB_18001235b
       180012345 48  8b  cf       MOV        param_1 ,RDI
                             LAB_180012348                                   XREF[1]:     180012359 (j)  
       180012348 8b  44  8c       MOV        EAX ,dword ptr [RSP  + param_1 *0x4  + local_1c8 ]
                 7c
       18001234c 33  c2           XOR        EAX ,param_2
       */
        
        $xor_reg = {
                   BA ?? ?? ?? ??
                   C7 4? [2-4] ?? ?? ?? ??
                   C7 4? [2-4] ?? ?? ?? ?? [10-30] 
                   33 C2
        } 

    condition:
        uint16be(0) == 0x4D5A and       
        #xor_hash > 5 and
        #xor_reg > 5


}
