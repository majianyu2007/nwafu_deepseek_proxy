"""Request-scoped logging; configuration is explicit at startup."""

import logging
from contextvars import ContextVar

logger = logging.getLogger("proxy")
request_id_ctx = ContextVar("request_id", default="-")


class _RequestIDFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        return True


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [%(request_id)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    _request_id_filter = _RequestIDFilter()
    _root_logger = logging.getLogger()
    for _h in _root_logger.handlers:
        if not any(isinstance(f, _RequestIDFilter) for f in _h.filters):
            _h.addFilter(_request_id_filter)

    for _name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        _l = logging.getLogger(_name)
        _l.handlers.clear()
        _l.propagate = True
