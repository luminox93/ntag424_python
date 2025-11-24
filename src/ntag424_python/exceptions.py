class NtagError(Exception):
    """Base exception for NTAG424 operations."""
    pass

class ConnectionError(NtagError):
    """Raised when connection to the tag fails."""
    pass

class AuthenticationError(NtagError):
    """Raised when authentication fails."""
    pass

class CommandError(NtagError):
    """Raised when a card command returns an error status."""
    pass
