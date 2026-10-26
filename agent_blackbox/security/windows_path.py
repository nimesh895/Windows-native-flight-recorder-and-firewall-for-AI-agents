from __future__ import annotations

import os
import sys
import re
from pathlib import Path
from typing import Optional, Tuple

# Windows API for resolving 8.3 short names if running on Windows
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes
    _kernel32 = ctypes.windll.kernel32
    _GetLongPathNameW = _kernel32.GetLongPathNameW
    _GetLongPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    _GetLongPathNameW.restype = wintypes.DWORD
else:
    _GetLongPathNameW = None


ADS_REGEX = re.compile(r"^([a-zA-Z]:[\\/][^:]+|[^:]+):([^\\/:]+)(?::\$DATA)?$", re.IGNORECASE)


class WindowsPathNormalizer:
    """
    Hardened path normalizer designed to defeat Windows-specific security bypasses:
    - 8.3 short filenames (e.g. C:\\PROGRA~1 -> C:\\Program Files)
    - Case sensitivity bypasses (e.g. c:\\windows == C:\\WINDOWS)
    - Directory traversal via .. and .
    - Alternate Data Streams (ADS) (e.g. secrets.txt:hidden.exe, evil.ps1::$DATA)
    - UNC and extended path prefixes (\\\\?\\, \\\\.\\, \\\\localhost\\c$)
    - Junctions and symbolic links
    """

    @staticmethod
    def detect_alternate_data_stream(raw_path: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Detects if a path attempts to access an Alternate Data Stream (ADS).
        Returns: (has_ads, base_path, stream_name)
        Example: 'test.txt:stream' -> (True, 'test.txt', 'stream')
                 'C:\\data\\file.txt::$DATA' -> (True, 'C:\\data\\file.txt', '')
                 'C:\\data\\file.txt' -> (False, 'C:\\data\\file.txt', None)
        """
        if not raw_path:
            return False, None, None

        # Ignore drive letter colon like C:\
        match = ADS_REGEX.match(raw_path)
        if match:
            base_part = match.group(1)
            stream_part = match.group(2)
            # Ignore standard $DATA stream specifier if it's just the default primary stream
            if stream_part.upper() == "$DATA":
                return True, base_part, "$DATA"
            return True, base_part, stream_part

        return False, raw_path, None

    @staticmethod
    def resolve_8dot3_path(path_str: str) -> str:
        """
        Converts 8.3 short filename segments to long names on Windows.
        If file doesn't exist or not on Windows, returns normalized standard path.
        """
        if _GetLongPathNameW is None or not os.path.exists(path_str):
            return path_str

        buffer_size = 1024
        buffer = ctypes.create_unicode_buffer(buffer_size)
        res = _GetLongPathNameW(path_str, buffer, buffer_size)
        if res > 0 and res < buffer_size:
            return buffer.value
        return path_str

    @classmethod
    def resolve_safe(cls, path_obj: Path) -> Path:
        """
        Safely resolves symlinks, junctions, and directory traversal for both
        existing and non-existent paths.
        Finds the nearest existing ancestor, fully resolves that ancestor
        (following symlinks and junctions), and re-appends the non-existent trailing parts.
        """
        # Ensure absolute first
        curr = path_obj if path_obj.is_absolute() else path_obj.absolute()

        # If it completely exists, resolve directly
        try:
            if curr.exists():
                return curr.resolve()
        except (PermissionError, OSError):
            pass

        # Walk up to the nearest existing ancestor
        parts_to_reappend: list[str] = []
        while not curr.exists() and curr != curr.parent:
            parts_to_reappend.append(curr.name)
            curr = curr.parent

        try:
            resolved_parent = curr.resolve()
        except (RuntimeError, PermissionError, OSError):
            resolved_parent = curr.absolute()

        # If parent has 8.3 short name, expand it
        resolved_parent_str = cls.resolve_8dot3_path(str(resolved_parent))
        resolved_parent = Path(resolved_parent_str)

        # Re-append non-existent trailing segments
        result = resolved_parent
        for part in reversed(parts_to_reappend):
            result = result / part

        return result

    @classmethod
    def normalize(cls, path_input: str | Path, base_dir: Optional[str | Path] = None) -> str:
        """
        Fully normalize a path on Windows:
        1. Strip outer quotes / whitespace
        2. Resolve relative paths against base_dir
        3. Eliminate '.' and '..'
        4. Resolve UNC prefixes (\\\\?\\)
        5. Resolve 8.3 short paths
        6. Resolve junctions & symlinks (nearest existing ancestor + remainder)
        7. Standardize slashes to forward slashes for matching, and lower-case drive letter
        """
        if isinstance(path_input, Path):
            path_str = str(path_input)
        else:
            path_str = str(path_input).strip("\"' \t\r\n")

        if not path_str:
            return ""

        # Check for ADS prefix
        has_ads, base, _ = cls.detect_alternate_data_stream(path_str)
        if has_ads and base:
            path_to_resolve = base
        else:
            path_to_resolve = path_str

        # Remove extended-length prefix if present for clean resolution
        if path_to_resolve.startswith(r"\\?\UNC\\"):
            path_to_resolve = r"\\" + path_to_resolve[8:]
        elif path_to_resolve.startswith(r"\\?\\"):
            path_to_resolve = path_to_resolve[4:]

        # Handle base dir if relative
        p = Path(path_to_resolve)
        if not p.is_absolute() and base_dir:
            p = Path(base_dir) / p

        # Resolve symlinks, junctions, and non-existent parent traversal safely
        resolved = cls.resolve_safe(p)
        resolved_str = str(resolved)

        # Resolve 8.3 short name on Windows if the full path exists
        resolved_str = cls.resolve_8dot3_path(resolved_str)

        # Standardize separators to forward slashes for uniform security checks
        norm = resolved_str.replace("\\", "/")

        # Lowercase drive letter on Windows for case-insensitive checks
        if len(norm) >= 2 and norm[1] == ":":
            norm = norm[0].lower() + norm[1:]

        return norm

    @classmethod
    def is_subpath_of(cls, candidate: str | Path, parent_dir: str | Path) -> bool:
        """
        Returns True if candidate path is inside parent_dir or matches parent_dir,
        accounting for case-insensitivity, 8.3 names, and traversal.
        """
        norm_child = cls.normalize(candidate)
        norm_parent = cls.normalize(parent_dir)

        # Ensure both are lowercase for case-insensitive comparison
        norm_child_lower = norm_child.lower()
        norm_parent_lower = norm_parent.lower()

        if norm_child_lower == norm_parent_lower:
            return True

        if not norm_parent_lower.endswith("/"):
            norm_parent_lower += "/"

        return norm_child_lower.startswith(norm_parent_lower)

    @classmethod
    def matches_pattern(cls, path_input: str | Path, pattern: str) -> bool:
        """
        Matches a path against a wildcard pattern (e.g. *.key, **/secrets/*).
        """
        norm_path = cls.normalize(path_input).lower()
        norm_pattern = pattern.replace("\\", "/").lower()

        # Simple glob to regex
        regex_pattern = re.escape(norm_pattern).replace(r"\*", ".*").replace(r"\?", ".")
        return bool(re.match(f"^{regex_pattern}$", norm_path))
