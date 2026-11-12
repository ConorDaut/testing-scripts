import "hash"

rule BadApple_Known_Hashes
{
    meta:
        description = "Detects known bad_apple.mp3, run.sh and y.py by SHA-256"
        author      = "Conor"
        date        = "2026-11-11"
        reference   = "Found in /tmp/.apple on Debian Splunk box"

    condition:
        filesize < 50MB and
        (
            hash.sha256(0, filesize) == "fe6802da0feea2b0dcd67c59688dda4b8618718a7374093195866949744df42e" or  // bad_apple.mp3
            hash.sha256(0, filesize) == "d15ba310e28605e3f635c28131f2445721ac38b96fa04a64ae17149d9ca0f093" or  // run.sh
            hash.sha256(0, filesize) == "506200eb040b9873100f8c390675d3d4842e9b0b97de3e0732b43705dab5ad54"     // y.py
        )
}

rule BadApple_Script_Heuristic
{
    meta:
        description = "Heuristic match for modified run.sh / y.py of the Bad Apple ASCII player"
        author      = "Conor"
        date        = "2026-11-11"
        note        = "String list is a best guess; refine after reading the scripts"

    strings:
        $name1 = "bad_apple"    nocase
        $name2 = "frames-ascii" nocase
        $path1 = "/tmp/.apple"
        $sh    = /^#!\/(usr\/)?bin\/(env )?(ba)?sh/
        $py    = /^#!\/(usr\/)?bin\/(env )?python/
        $play1 = "mpg123"
        $play2 = "ffplay"
        $play3 = "aplay"
        $play4 = "cvlc"

    condition:
        filesize < 200KB and
        (
            2 of ($name*, $path1) or
            (1 of ($name*) and 1 of ($play*) and ($sh at 0 or $py at 0))
        )
}
