rule Cobalt_Strike_Beacon {
    meta:
        author = "muzi"
        date = "2021-07-04"
    strings:
        $s1 = "MZRE"
        $s2 = "MZAR"
        $s3 = "could not run command (w/ token) because of its length of %d bytes!"
        $s4 = "could not spawn %s (token): %d"
        $s5 = "could not spawn %s: %d"
        $s6 = "Could not open process token: %d (%u)"
        $s7 = "could not run %s as %s\\%s: %d"
        $s8 = "could not upload file: %d"
        $s9 = "could not open %s: %d"
        $s10 = "could not get file time: %d"
        $s11 = "could not set file time: %d"
        $s12 = "Could not connect to pipe (%s): %d"
        $s13 = "Could not open service control manager on %s: %d"
        $s14 = "Could not create service %s on %s: %d"
        $s15 = "Could not start service %s on %s: %d" 
        $s16 = "Failed to impersonate token: %d"
        $s17 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset."
        $s18 = "could not write to process memory: %d"
        $s19 = "could not create remote thread in %d: %d"
        $s20 = "%d is an x64 process (can't inject x86 content)"
        $s21 = "%d is an x86 process (can't inject x64 content)"
        $s22 = "Could not connect to pipe: %d"
        $s23 = "kerberos ticket use failed: %08x"
        $s24 = "could not connect to pipe: %d"
        $s25 = "Maximum links reached. Disconnect one"
        $s26 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')"
        $s27 = "I'm already in SMB mode"
        $s28 = "Failed to duplicate primary token for %d (%u)"
        $s29 = "Failed to impersonate logged on user %d (%u)"
        $s30 = "LibTomMath"
        $s31 = "beacon.dll"
        $s32 = "ReflectiveLoader@4"
    condition:
        6 of them

}

