"""One JSON request on stdin; no generated Python or secrets on argv."""

import json
import sys
from . import dispatch, SCHEMA_VERSION


def main():
    try:
        raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("Request exceeds 2 MiB")
        response = dispatch(json.loads(raw))
    except Exception as exc:
        # Never echo the request or exception message: either can contain credentials.
        response = {"schema_version": SCHEMA_VERSION, "error": type(exc).__name__}
    print(json.dumps(response))


if __name__ == "__main__":
    main()
