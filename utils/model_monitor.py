"""Compatibility imports; runtime monitoring lives in nwafu_proxy.monitor."""

from nwafu_proxy.monitor import ModelMonitor, create_monitor, register_monitor_routes

__all__ = ["ModelMonitor", "create_monitor", "register_monitor_routes"]
