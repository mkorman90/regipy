class RegipyException(Exception):
    """
    This is the parent exception for all regipy exceptions
    """
    pass


class RegipyGeneralException(RegipyException):
    """
    General exception
    """
    pass


class RegistryValueNotFoundException(RegipyException):
    pass


class NoRegistrySubkeysException(RegipyException):
    pass


class NoRegistryValuesException(RegipyException):
    pass


class RegistryKeyNotFoundException(RegipyException):
    pass


class UnidentifiedHiveException(RegipyException):
    pass

