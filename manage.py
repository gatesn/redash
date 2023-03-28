#!/usr/bin/env python
"""
CLI to manage redash.
"""

from redash.cli import manager

if __name__ == '__main__':
    import signal
    setattr(signal, 'SIGRTMIN', signal.SIGTERM)
    setattr(signal, 'SIGRTMAX', signal.SIGTERM)
    manager()
