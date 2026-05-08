"""
Case 061: minimal reproduction of command injection in async_run (Bcfg2 Trigger plugin).
Keeps the os.system sink semantics for Bandit / repair detection.
"""

import os

def async_run(prog, args):
    """
    VULNERABLE: concatenates prog and args into one shell string for os.system.
    Shell metacharacters in args (e.g. ';') become command separators.
    """
    os.system(" ".join([prog] + args))


def run_command(prog, args):
    """Thin wrapper for callers / tests that import a single entrypoint."""
    async_run(prog, args)
