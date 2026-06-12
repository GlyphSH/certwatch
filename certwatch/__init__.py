"""certwatch — a TLS certificate & configuration grader."""

__version__ = "0.1.0"

from .core import Result, check_host, grade

__all__ = ["Result", "check_host", "grade", "__version__"]
