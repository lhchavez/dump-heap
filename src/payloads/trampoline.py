import threading


def __wrapper() -> None:
    import gc

    OUTPUT_PATH = "{output_path}"
    DONE_PATH = "{done_path}"

    exc: BaseException | None = None
    try:
        __payload_entrypoint(OUTPUT_PATH)
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


__dump_heap_thread = threading.Thread(target=__wrapper, daemon=True)
__dump_heap_thread.start()
