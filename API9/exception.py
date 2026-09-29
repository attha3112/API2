class SecurityAlertError(Exception):
    """Memicu error saat percobaan login gagal melebihi ambang batas keamanan."""
    pass

class InvalidLogFormatError(Exception):
    """Memicu error saat format data log server tidak sesuai spesifikasi."""
    pass