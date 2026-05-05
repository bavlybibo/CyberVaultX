from __future__ import annotations


class CyberVaultError(Exception):
    """Base class for user-safe CyberVault exceptions."""


class VaultLockedError(CyberVaultError):
    """Raised when a vault operation requires an unlocked master key."""


class VaultIntegrityError(CyberVaultError):
    """Raised when encrypted vault data fails integrity validation."""


class UnsafeSecretHandlingError(CyberVaultError):
    """Raised when an operation would expose a protected secret."""


class ConfigurationError(CyberVaultError):
    """Raised when settings or runtime configuration are invalid."""
