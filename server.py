"""Compatibility entry point: python server.py or uvicorn server:app."""

from nwafu_proxy.app import create_app
from nwafu_proxy.cli import main


def __getattr__(name: str):
    # Uvicorn's legacy server:app target remains supported without eager config I/O.
    if name == "app":
        from nwafu_proxy.logging import configure_logging

        configure_logging()
        app = create_app()
        globals()["app"] = app
        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    main()
