def invoice_filename(reference: str) -> str:
    return f"invoice-{reference.strip()}.pdf"
