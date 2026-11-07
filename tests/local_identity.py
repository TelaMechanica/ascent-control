"""The local account name, for tests that prove it never reaches an artefact.

The username must not appear as a literal anywhere in this repository -- it leaks a
real person's account into every clone. But the tests that assert it is SCRUBBED need
something to scrub, and a hardcoded placeholder proves nothing: a scrubber that only
catches the word "testuser" would pass while leaking the real one.

So it is read from the environment at run time. On a machine where it cannot be
determined the tests that depend on it skip, rather than quietly testing nothing.
"""

import getpass
import os


def local_username() -> str | None:
    for source in (lambda: os.environ.get("USER"),
                   lambda: os.environ.get("USERNAME"),
                   getpass.getuser):
        try:
            name = source()
        except Exception:
            name = None
        if name and name.strip():
            return name.strip()
    return None


def home() -> str:
    return os.path.expanduser("~")
