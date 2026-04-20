rule text_user_agent_header
{
    meta:
        description = "Detects User-Agent header in text output"

    strings:
        $ua = "User-Agent:" ascii wide nocase

    condition:
        $ua
}
