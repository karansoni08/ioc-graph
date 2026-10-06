"""Ingestion errors.

`IngestError` messages are written to be shown directly to a user, so they must never carry
a stack trace, a file path outside the upload name, or any secret.
"""

from __future__ import annotations


class IngestError(Exception):
    """A problem with an uploaded file that the user can understand and act on."""
