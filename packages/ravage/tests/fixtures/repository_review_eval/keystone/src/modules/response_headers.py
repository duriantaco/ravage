def normalize_response_headers(value: str) -> str:
    return " ".join(value.strip().split())
