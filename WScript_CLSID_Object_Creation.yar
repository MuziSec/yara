rule WScript_CLSID_Object_Creation {
    meta:
    author = "muzi"
    date = "2021-12-02"
    description = "Detects various CLSIDs used to create objects rather than their object name."
    hash = "9b36b76445f76b411983d5fb8e64716226f62d284c673599d8c54decdc80c712"

    strings:
        $clsid_windows_script_host_shell_object = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii wide nocase
        $clsid_shell = "13709620-C279-11CE-A49E-444553540000" ascii wide nocase
        $clsid_mmc = "49B2791A-B1AE-4C90-9B8E-E860BA07F889" ascii wide nocase
        $clsid_windows_script_host_shell_object_2 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii wide nocase
        $clsid_filesystem_object = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii wide nocase

    condition:

        any of them

}
