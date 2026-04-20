rule test_any_pe_binary
{
    meta:
        description = "Matches most Windows PE executables and DLLs"
        author = "LivChat"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0
}
