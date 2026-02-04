# stream_framing.py
"""
Simple length-prefixed framing for TCP stream correctness.
"""
from __future__ import annotations

import struct
from typing import List, Tuple


def frame_bytes(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def deframe(buffer: bytes) -> Tuple[List[bytes], bytes]:
    frames: List[bytes] = []
    offset = 0
    while True:
        if len(buffer) - offset < 4:
            break
        (length,) = struct.unpack("!I", buffer[offset:offset + 4])
        if len(buffer) - offset - 4 < length:
            break
        start = offset + 4
        end = start + length
        frames.append(buffer[start:end])
        offset = end
    return frames, buffer[offset:]
