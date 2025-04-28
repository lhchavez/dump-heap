import asyncio
import threading
from typing import Any


def __wrapper(event_loop: Any | None) -> None:
    import gc

    OUTPUT_PATH = "{output_path}"
    DONE_PATH = "{done_path}"

    exc: BaseException | None = None
    try:
        __payload_entrypoint(OUTPUT_PATH, event_loop)
    except BaseException as e:
        exc = e
    finally:
        try:
            del globals()["__payload_entrypoint"]
        except:  # noqa: E722
            pass
        gc.collect()

    with open(DONE_PATH, "w") as done_file:
        if exc is None:
            done_file.write("SUCCESS")
        else:
            done_file.write(f"ERROR: \{exc}")


__event_loop: Any | None
try:
    __event_loop = asyncio.get_event_loop()
except:
    __event_loop = None
__dump_heap_thread = threading.Thread(
    target=__wrapper,
    daemon=True,
    args=(__event_loop,),
)
__dump_heap_thread.start()
