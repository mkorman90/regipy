from .registry import *  # noqa: F401, F403

__title__ = "regipy"
__version__ = "6.2.1"

# Opt-in Rust acceleration: set REGIPY_BACKEND=rust to enable.
from . import _rust_backend as _rust_backend  # noqa: E402

_rust_backend.maybe_install()
