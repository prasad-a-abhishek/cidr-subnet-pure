"""Exception hierarchy."""


class CIDRError(ValueError):
    """Base class for every error this library raises."""


class InvalidCIDR(CIDRError):
    """Raised when a string cannot be parsed as a CIDR block."""


class MixedFamilyError(TypeError, CIDRError):
    """Raised when an operation mixes IPv4 and IPv6 inputs.
    Inherits TypeError so AC-15's ``except TypeError`` still catches it.
    """
