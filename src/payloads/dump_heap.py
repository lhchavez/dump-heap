def __payload_entrypoint(output_path: str) -> None:
    import asyncio
    import inspect
    import logging
    import gc
    import struct
    import sys
    from typing import Any

    MAX_PAYLOAD_SIZE = 128
    RECORD_DONE = 0
    RECORD_TYPE = 1
    RECORD_OBJECT = 2
    RECORD_OBJECT_WITH_PAYLOAD = 3
    RECORD_REFERENTS = 4

    logging.warning("XXX: dump_heap: writing report to %r", output_path)
    logging.warning("XXX: dump_heap: collecting gc")
    gc.collect()
    seen: set[int] = set()
    seentypes: set[type] = set()
    ignored_addrs = {id(seen), id(seentypes)}
    ignored_addrs.add(id(ignored_addrs))
    logging.warning("XXX: dump_heap: collected gc")

    def _get_payload(obj: Any) -> bytes | None:
        try:
            payload_str: str | None = None
            payload: bytes | None = None
            if isinstance(obj, str):
                payload_str = obj
            elif isinstance(obj, dict):
                payload_entries: list[bytes] = []
                payload_length = 0
                for key in obj.keys():
                    if isinstance(key, bytes):
                        if len(key) > MAX_PAYLOAD_SIZE:
                            key_bytes = key[:MAX_PAYLOAD_SIZE]
                        else:
                            key_bytes = key
                    elif isinstance(key, str):
                        if len(key) > MAX_PAYLOAD_SIZE:
                            key_bytes = key[:MAX_PAYLOAD_SIZE].encode(
                                "utf-8", "replace"
                            )
                        else:
                            key_bytes = key.encode("utf-8", "replace")
                    else:
                        key_str = str(key)
                        if len(key_str) > MAX_PAYLOAD_SIZE:
                            key_bytes = key_str[:MAX_PAYLOAD_SIZE].encode(
                                "utf-8", "replace"
                            )
                        else:
                            key_bytes = key_str.encode("utf-8", "replace")
                    payload_entries.append(key_bytes)
                    payload_length += len(key_bytes) + 1
                    if payload_length > MAX_PAYLOAD_SIZE:
                        break
                payload = b",".join(payload_entries)
                del payload_entries
            elif isinstance(obj, asyncio.Task):
                payload_str = obj.get_name()
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

            if payload_str is not None and payload is None:
                if len(payload_str) <= MAX_PAYLOAD_SIZE:
                    payload = payload_str.encode("utf-8", "replace")
                else:
                    payload = payload_str[:MAX_PAYLOAD_SIZE].encode("utf-8", "replace")
                del payload_str
            if payload is not None and len(payload) > MAX_PAYLOAD_SIZE:
                payload = payload[:MAX_PAYLOAD_SIZE]
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
                        struct.pack(
                            f"!BQH{len(typename)}s",
                            RECORD_TYPE,
                            objtype_addr,
                            len(typename),
                            typename,
                        )
                    )
                    seentypes.add(objtype)

                size = sys.getsizeof(obj, 0)
                totalsize += size
                payload = _get_payload(obj)
                if payload is not None:
                    output_file.write(
                        struct.pack(
                            f"!B?QQLH{len(payload)}s",
                            RECORD_OBJECT_WITH_PAYLOAD,
                            root,
                            addr,
                            objtype_addr,
                            size,
                            len(payload),
                            payload,
                        )
                    )
                else:
                    output_file.write(
                        struct.pack(
                            "!B?QQL",
                            RECORD_OBJECT,
                            root,
                            addr,
                            objtype_addr,
                            size,
                        )
                    )

                # The format is "!BQH{len(referents)}Q"
                referents = gc.get_referents((obj))
                output_file.write(
                    struct.pack(
                        "!BQH",
                        RECORD_REFERENTS,
                        addr,
                        len(referents),
                    )
                )
                for child_obj in referents:
                    child_addr = id(child_obj)
                    output_file.write(
                        struct.pack(
                            "Q",
                            child_addr,
                        )
                    )
                    queue.append((child_obj, child_addr, False))
                del referents

            output_file.write(struct.pack("!B", RECORD_DONE))

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
