rule text_privilege_escalation
{
    meta:
        description = "Privilege escalation indicators"

    strings:
        $a = "SeTakeOwnershipPrivilege" nocase ascii wide
        $b = "SeDebugPrivilege" nocase ascii wide
        $c = "SeImpersonatePrivilege" nocase ascii wide
        $d = "SeLoadDriverPrivilege" nocase ascii wide

    condition:
        any of them
}

rule text_token_manipulation
{
    meta:
        description = "Token manipulation APIs"

    strings:
        $a = "AdjustTokenPrivileges" nocase ascii wide
        $b = "OpenProcessToken" nocase ascii wide

    condition:
        any of them
}

rule text_crypto_operations
{
    meta:
        description = "Cryptographic API usage"

    strings:
        $a = "CryptEncrypt" nocase ascii wide
        $b = "CryptDecrypt" nocase ascii wide
        $c = "BCryptEncrypt" nocase ascii wide
        $d = "BCryptDecrypt" nocase ascii wide

    condition:
        any of them
}

rule text_c2_indicator
{
    meta:
        description = "Possible hardcoded IP URL"

    strings:
        $a = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/ ascii

    condition:
        $a
}

rule text_process_injection
{
    meta:
        description = "Process injection indicators"

    strings:
        $a = "WriteProcessMemory" ascii wide
        $b = "NtCreateThreadEx" ascii wide
        $c = "RtlCreateUserThread" ascii wide
        $d = "VirtualAlloc" ascii wide
        $e = "PAGE_EXECUTE" ascii wide

    condition:
        any of ($a,$b,$c) or ($d and $e)
}

rule text_anti_debug
{
    meta:
        description = "Anti-debugging technique"

    strings:
        $a = "IsDebuggerPresent" ascii wide
        $b = "NtQueryInformationProcess" ascii wide

    condition:
        any of them
}
