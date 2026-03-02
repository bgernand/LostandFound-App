try:
    from .main import app  # noqa: F401
except ModuleNotFoundError:
    # Allow CLI modules (e.g. `python -m lfapp.cli`) to run even if Flask
    # dependencies are not installed in the current interpreter.
    app = None  # type: ignore
