class VulnParserError(Exception):
    """Base exception for vulnerability parser"""
    pass

class DriverNotFoundError(VulnParserError):
    """Raised when web driver not found"""
    pass

class PageLoadError(VulnParserError):
    """Raised when page loading fails"""
    pass

class ParseError(VulnParserError):
    """Raised when parsing fails"""
    pass

class SaveToExcelError(VulnParserError):
    """Raised when saving to Excel fails"""
    pass