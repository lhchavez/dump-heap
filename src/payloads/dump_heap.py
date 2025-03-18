def __payload_entrypoint(output_path: str) -> None:
    import asyncio
    import asyncio.events
    import inspect
    import logging
    import gc
    import struct
    import sys
    from typing import Any

    DEFAULT_MAX_PAYLOAD_SIZE = 128

    logging.warning("XXX: dump_heap: writing report to %r", output_path)
    logging.warning("XXX: dump_heap: collecting gc")
    gc.collect()
    gc.collect(1)
    gc.collect(2)
    seen: set[int] = set()
    seentypes: set[type] = set()
    ignored_addrs = {id(seen), id(seentypes)}
    ignored_addrs.add(id(ignored_addrs))
    logging.warning("XXX: dump_heap: collected gc")

    # Handrolled msgpack packer.
    # See https://github.com/msgpack/msgpack/blob/master/spec.md for reference.
    def _pack_map(map_len: int) -> bytes:
        if map_len < 0x10:
            return struct.pack("!B", 0x80 | map_len)
        if map_len < 0x10000:
            return struct.pack("!BH", 0xDE, map_len)
        if map_len < 0x100000000:
            return struct.pack("!BI", 0xDF, map_len)
        raise ValueError("too big of a map")

    def _pack_array(array_len: int) -> bytes:
        if array_len < 0x10:
            return struct.pack("!B", 0x90 | array_len)
        if array_len < 0x10000:
            return struct.pack("!BH", 0xDC, array_len)
        if array_len < 0x100000000:
            return struct.pack("!BI", 0xDD, array_len)
        raise ValueError("too big of an array")

    def _pack_int(value: int) -> bytes:
        if value < 0:
            raise ValueError("negative integers not supported")
        if value < 0x80:
            return struct.pack("!B", 0x00 | value)
        if value < 0x100:
            return struct.pack("!BB", 0xCC, value)
        if value < 0x10000:
            return struct.pack("!BH", 0xCD, value)
        if value < 0x100000000:
            return struct.pack("!BI", 0xCE, value)
        if value < 0x10000000000000000:
            return struct.pack("!BQ", 0xCF, value)
        raise ValueError("too big of a number")

    def _pack_str(value: bytes) -> bytes:
        value_len = len(value)
        if value_len < 0x20:
            return struct.pack(f"!B{value_len}s", 0xA0 | value_len, value)
        if value_len < 0x100:
            return struct.pack(f"!BB{value_len}s", 0xD9, value_len, value)
        if value_len < 0x10000:
            return struct.pack(f"!BH{value_len}s", 0xDA, value_len, value)
        if value_len < 0x100000000:
            return struct.pack(f"!BI{value_len}s", 0xDB, value_len, value)
        raise ValueError("too big of a string")

    def _pack_bin(value: bytes) -> bytes:
        value_len = len(value)
        if value_len < 0x100:
            return struct.pack(f"!BB{value_len}s", 0xC4, value_len, value)
        if value_len < 0x10000:
            return struct.pack(f"!BH{value_len}s", 0xC5, value_len, value)
        if value_len < 0x100000000:
            return struct.pack(f"!BI{value_len}s", 0xC6, value_len, value)
        raise ValueError("too big of a bytes")

    def _pack_bool(value: bool) -> bytes:
        if value:
            return b"\xc3"
        return b"\xc2"

    def _pack_done() -> bytes:
        return b"".join(
            (
                _pack_map(1),
                #
                _pack_str(b"t"),
                _pack_str(b"done"),
            )
        )

    def _pack_type(objtype_addr: int, typename: bytes) -> bytes:
        return b"".join(
            (
                _pack_map(3),
                #
                _pack_str(b"t"),
                _pack_str(b"type"),
                #
                _pack_str(b"objtype_addr"),
                _pack_int(objtype_addr),
                #
                _pack_str(b"typename"),
                _pack_str(typename),
            )
        )

    def _pack_object(
        *, root: bool, addr: int, objtype_addr: int, size: int, payload: bytes | None
    ) -> bytes:
        if payload:
            return b"".join(
                (
                    _pack_map(6),
                    #
                    _pack_str(b"t"),
                    _pack_str(b"object"),
                    #
                    _pack_str(b"root"),
                    _pack_bool(root),
                    #
                    _pack_str(b"objtype_addr"),
                    _pack_int(objtype_addr),
                    #
                    _pack_str(b"addr"),
                    _pack_int(addr),
                    #
                    _pack_str(b"size"),
                    _pack_int(size),
                    # The payload is not guaranteed to be UTF-8.
                    _pack_str(b"payload"),
                    _pack_bin(payload),
                )
            )
        else:
            return b"".join(
                (
                    _pack_map(5),
                    #
                    _pack_str(b"t"),
                    _pack_str(b"object"),
                    #
                    _pack_str(b"root"),
                    _pack_bool(root),
                    #
                    _pack_str(b"objtype_addr"),
                    _pack_int(objtype_addr),
                    #
                    _pack_str(b"addr"),
                    _pack_int(addr),
                    #
                    _pack_str(b"size"),
                    _pack_int(size),
                )
            )

    def _pack_referents(*, addr: int, child_addrs: list[int]) -> bytes:
        return b"".join(
            (
                _pack_map(3),
                #
                _pack_str(b"t"),
                _pack_str(b"referents"),
                #
                _pack_str(b"addr"),
                _pack_int(addr),
                #
                _pack_str(b"child_addrs"),
                _pack_array(len(child_addrs)),
                *(_pack_int(a) for a in child_addrs),
            )
        )

    def _get_payload(obj: Any) -> bytes | None:
        try:
            payload_str: str | None = None
            payload: bytes | None = None
            max_payload_size = DEFAULT_MAX_PAYLOAD_SIZE
            if isinstance(obj, str):
                payload_str = obj
            elif isinstance(obj, dict):
                payload_entries: list[bytes] = []
                payload_length = 0
                for key in obj.keys():
                    if isinstance(key, bytes):
                        if len(key) > max_payload_size:
                            key_bytes = key[:max_payload_size]
                        else:
                            key_bytes = key
                    elif isinstance(key, str):
                        if len(key) > max_payload_size:
                            key_bytes = key[:max_payload_size].encode(
                                "utf-8", "replace"
                            )
                        else:
                            key_bytes = key.encode("utf-8", "replace")
                    else:
                        key_str = str(key)
                        if len(key_str) > max_payload_size:
                            key_bytes = key_str[:max_payload_size].encode(
                                "utf-8", "replace"
                            )
                        else:
                            key_bytes = key_str.encode("utf-8", "replace")
                    payload_entries.append(key_bytes)
                    payload_length += len(key_bytes) + 1
                    if payload_length > max_payload_size:
                        break
                payload = b",".join(payload_entries)
                del payload_entries
            elif isinstance(obj, asyncio.Task):
                payload_str = obj.get_name()
            elif isinstance(obj, asyncio.events.Handle):
                max_payload_size = 4096
                # The important bits in the stack frames are always towards at
                # the bottom. So we revert it for simplicity.
                source_traceback = obj._source_traceback  # type: ignore[attr-defined]
                payload_str = (
                    "\n".join(repr(frame) for frame in source_traceback[::-1])
                    if source_traceback
                    else repr(obj)
                )
            elif inspect.ismodule(obj):
                payload_str = obj.__name__
            elif inspect.isclass(obj):
                payload_str = obj.__qualname__
            elif inspect.ismethod(obj):
                func = obj.__func__
                payload_str = f"{func.__qualname__} at {func.__code__.co_filename}:{func.__code__.co_firstlineno}"
            elif inspect.isfunction(obj):
                payload_str = f"{obj.__qualname__} at {obj.__code__.co_filename}:{obj.__code__.co_firstlineno}"
            elif inspect.iscoroutine(obj):
                payload_str = obj.__qualname__

            if payload is None and payload_str is not None:
                if len(payload_str) <= max_payload_size:
                    payload = payload_str.encode("utf-8", "replace")
                else:
                    payload = payload_str[:max_payload_size].encode("utf-8", "replace")
            del payload_str
        except:  # noqa: E722
            pass
        return payload

    try:
        with open(output_path, "wb") as output_file:
            queue: list[tuple[Any, int, bool]] = [
                (o, id(o), True) for o in gc.get_objects()
            ]
            x = 0
            totalsize = 0

            while queue:
                if x % 100_000 == 0:
                    logging.warning(
                        "XXX: dump_heap: %d / %d (%5.2f MiB)",
                        x,
                        len(queue),
                        totalsize / 1024.0 / 1024.0,
                    )
                x += 1

                obj, addr, root = queue.pop()
                if addr in ignored_addrs:
                    # We don't want to track the objects we own.
                    continue
                if addr in seen:
                    continue

                seen.add(addr)
                objtype = type(obj)
                objtype_addr = id(objtype)
                if objtype not in seentypes:
                    typename = (f"{objtype.__module__}.{objtype.__name__}").encode(
                        "utf-8",
                        "replace",
                    )
                    output_file.write(
                        _pack_type(
                            objtype_addr=objtype_addr,
                            typename=typename,
                        )
                    )
                    seentypes.add(objtype)

                size = sys.getsizeof(obj, 0)
                totalsize += size
                output_file.write(
                    _pack_object(
                        root=root,
                        addr=addr,
                        objtype_addr=objtype_addr,
                        size=size,
                        payload=_get_payload(obj),
                    )
                )

                referents = gc.get_referents((obj))
                child_addrs: list[int] = []
                for child_obj in referents:
                    child_addr = id(child_obj)
                    child_addrs.append(child_addr)
                    queue.append((child_obj, child_addr, False))
                if child_addrs:
                    output_file.write(
                        _pack_referents(addr=addr, child_addrs=child_addrs)
                    )
                del referents
                del child_addrs

            output_file.write(_pack_done())

            logging.warning(
                "XXX: dump_heap: %d / %d (%5.2f MiB)",
                x,
                len(queue),
                totalsize / 1024.0 / 1024.0,
            )
            del queue
    except:
        logging.exception("XXX: dump_heap: failed to collect")
        raise
    finally:
        del seen
        del seentypes
        del ignored_addrs
