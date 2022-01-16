rule Agent_Tesla_Aggah {
    meta:
    author = "muzi"
    date = "2021-12-02"
    description = "Detects Agent Tesla delivered by Aggah Campaign in November 2021."
    hash = "3bb3440898b6e2b0859d6ff66f760daaa874e1a25b029c0464944b5fc2f5a903"

    strings:

        $string_decryption = {
                               91                           // byte array[i]
                               (06|07|08|09)                // push local var
                               61                           // xor array[i] ^ 0xAA (const xor key)
                               20 [4]                       // push const xor key (170 or 0xAA in example)
                               61                           // xor array[i] ^ i
                               D2                           // convert to unsigned int8 and push int32 to stack
                               9C                           // Replace array element at index with int8 value on stack
                               (06|07|08|09)                // push local var
                               17                           // push 1
                               58                           // add i +=1
                               (0A|0B|0C|0D)                // pop value from stack into local var
                               (06|07|08|09)                // push local var
                               7E [4]                       // push value of static field on stack (byte array)
                               8E                           // push length of array onto stack
                               69                           // convert to int32
                               FE (04|05)                   // conditional if i >= len(bytearray)
        }

    condition:

        all of them

}
