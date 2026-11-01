from parser import parse_untrusted_payload, format_safe_label

def process_user_upload(data: str):
    clean_header = format_safe_label("config_upload")
    return parse_untrusted_payload(data)
