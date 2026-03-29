try:
    from .main import app  # noqa: F401
except (ModuleNotFoundError, RuntimeError):
    # Allow CLI modules (e.g. `python -m lfapp.cli`) to run even if Flask
    # dependencies are not installed in the current interpreter, or when
    # first-start credentials are intentionally provided later via create_app().
    app = None  # type: ignore
