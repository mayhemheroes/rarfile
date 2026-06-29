#!/usr/bin/env python3
"""Structure-aware Atheris fuzz harness for rarfile.

rarfile parses a checksummed binary container (RAR), so random bytes essentially
never form a valid archive — a naive harness bounces off the signature/header-CRC
checks and never reaches the parser (coverage plateaus). To exercise the parser on
EVERY input (so coverage climbs from an empty corpus, no seed corpus required),
this harness SYNTHESIZES a structurally-valid RAR5 archive whose block count,
block types and header fields are all driven by the fuzzed bytes, then hands it to
rarfile.RarFile(...).

RAR5 layout (see rarfile.py: RAR5_ID, _parse_block_header, _parse_file_block,
_process_file_extra). Each block is:
  crc32_le(4) | header_size(vint) | <header payload of header_size bytes>
header payload:  block_type(vint) block_flags(vint) [extra_size(vint) if EXTRA_DATA]
                 [add_size(vint) if DATA_AREA] <type-specific fields...> [extra records]
The header CRC is zlib.crc32 over everything after the 4-byte CRC field. By driving
the file flags (mtime/crc32/dir), the compression flags, host OS, the name, AND the
optional EXTRA_DATA records (TIME/HASH/VERSION/REDIR/OWNER) from the fuzzer, the real
header parser (vint/vstr/unixtime decoding, extra-record dispatch, dir handling) runs
on each input. infolist()/namelist() validate HEADER structure (the data-section CRC
is only checked on extraction), which is exactly this surface.
"""
import io
import struct
import sys
import zlib

import atheris

# The Atheris fuzzing utilities shipped with the original fuzz-rar target.
import fuzz_helpers

# Instrument only the library under test (scoped — instrumenting stdlib too does
# not register as coverage in Mayhem and only adds noise).
with atheris.instrument_imports(include=["rarfile"]):
    import rarfile

_SIG = b"Rar!\x1a\x07\x01\x00"

# RAR5 block types / flags / extra-record types (mirror rarfile.py constants).
_BLK_MAIN, _BLK_FILE, _BLK_SERVICE, _BLK_ENDARC = 1, 2, 3, 5
_BF_EXTRA, _BF_DATA = 0x01, 0x02
_XF_TIME, _XF_HASH, _XF_VERSION, _XF_REDIR, _XF_OWNER = 3, 2, 4, 5, 6


def _vint(n: int) -> bytes:
    """LEB128 variable-length int, as rarfile.load_vint expects."""
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _vstr(b: bytes) -> bytes:
    return _vint(len(b)) + b


def _block(block_type: int, body: bytes, data: bytes = b"",
           block_flags: int = 0, extra: bytes = b"") -> bytes:
    payload = _vint(block_type) + _vint(block_flags)
    if block_flags & _BF_EXTRA:
        payload += _vint(len(extra))
    if block_flags & _BF_DATA:
        payload += _vint(len(data))
    payload += body + extra
    # header_size vint counts the bytes AFTER itself (== len(payload)).
    after_crc = _vint(len(payload)) + payload
    crc = zlib.crc32(after_crc) & 0xFFFFFFFF
    return struct.pack("<I", crc) + after_crc + data


def _extra_record(fdp) -> bytes:
    """One EXTRA_DATA record: vint(size) | <xtype(vint) payload>."""
    xtype = fdp.PickValueInList([_XF_TIME, _XF_HASH, _XF_VERSION, _XF_REDIR, _XF_OWNER])
    rec = _vint(xtype)
    if xtype == _XF_TIME:
        flags = fdp.ConsumeIntInRange(0, 0x0F)
        rec += _vint(flags)
        # unix vs windows time width depends on the 0x01 (is-windows) flag.
        width = 8 if (flags & 0x01) else 4
        for _ in range(bin(flags & 0x0E).count("1")):
            rec += fdp.ConsumeBytes(width).ljust(width, b"\0")
    elif xtype == _XF_HASH:
        rec += _vint(0)  # BLAKE2sp hash-type marker
        rec += fdp.ConsumeBytes(32).ljust(32, b"\0")
    elif xtype == _XF_VERSION:
        rec += _vint(0) + _vint(fdp.ConsumeIntInRange(0, 0xFFFF))
    elif xtype == _XF_REDIR:
        rec += _vint(fdp.ConsumeIntInRange(0, 4)) + _vint(fdp.ConsumeIntInRange(0, 3))
        rec += _vstr(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 32)))
    elif xtype == _XF_OWNER:
        rec += _vint(fdp.ConsumeIntInRange(0, 0x0F))
        rec += _vstr(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 16)))
        rec += _vstr(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 16)))
    return _vint(len(rec)) + rec


def _file_like_block(fdp, block_type: int) -> bytes:
    file_flags = fdp.ConsumeIntInRange(0, 0x0F)
    file_size = fdp.ConsumeIntInRange(0, 0xFFFFFF)
    mode = fdp.ConsumeIntInRange(0, 0xFFFF)
    name = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 48)) or b"f"

    body = _vint(file_flags) + _vint(file_size) + _vint(mode)
    if file_flags & 0x02:  # HAS_MTIME (load_unixtime: 4 LE bytes)
        body += struct.pack("<I", fdp.ConsumeIntInRange(0, 0xFFFFFFFF))
    if file_flags & 0x04:  # HAS_CRC32
        body += struct.pack("<I", fdp.ConsumeIntInRange(0, 0xFFFFFFFF))
    compress_flags = fdp.ConsumeIntInRange(0, 0x7FFF)
    host_os = fdp.ConsumeIntInRange(0, 1)
    body += _vint(compress_flags) + _vint(host_os) + _vstr(name)

    extra = b""
    block_flags = 0
    n_extra = fdp.ConsumeIntInRange(0, 2)
    if n_extra:
        extra = b"".join(_extra_record(fdp) for _ in range(n_extra))
        block_flags |= _BF_EXTRA
    data = b""
    if block_type == _BLK_FILE:
        data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64))
        block_flags |= _BF_DATA
    return _block(block_type, body, data=data, block_flags=block_flags, extra=extra)


def _build_rar5(fdp) -> bytes:
    main_flags = fdp.ConsumeIntInRange(0, 0x1F)
    main_body = _vint(main_flags)
    if main_flags & 0x02:  # MAIN HAS_VOLNR
        main_body += _vint(fdp.ConsumeIntInRange(0, 0xFFFF))
    out = [_SIG, _block(_BLK_MAIN, main_body, block_flags=0)]

    for _ in range(fdp.ConsumeIntInRange(1, 4)):
        btype = fdp.PickValueInList([_BLK_FILE, _BLK_FILE, _BLK_SERVICE])
        out.append(_file_like_block(fdp, btype))

    out.append(_block(_BLK_ENDARC, _vint(fdp.ConsumeIntInRange(0, 1)), block_flags=0))
    return b"".join(out)


def TestOneInput(data: bytes) -> None:
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        archive = _build_rar5(fdp)
    except Exception:
        return
    try:
        rf = rarfile.RarFile(io.BytesIO(archive))
        for info in rf.infolist():
            _ = info.filename
            _ = info.file_size
            _ = info.compress_type
            _ = info.date_time
        rf.namelist()
        rf.needs_password()
        _ = rf.comment
    except rarfile.Error:
        # Library-defined errors are the expected outcome for malformed input.
        pass
    except (ValueError, EOFError, OSError):
        # Stream/value errors from pathological input are not defects.
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
