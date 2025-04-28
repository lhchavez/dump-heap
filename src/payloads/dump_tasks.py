from typing import Any


def __payload_entrypoint(output_path: str, event_loop: Any | None) -> None:
    import asyncio
    import asyncio.events
    import logging

    logging.warning("XXX: dump_tasks: writing report to %r", output_path)
    if event_loop is None:
        raise ValueError("no running event loop")
    try:
        with open(output_path, "w") as output_file:
            for task in asyncio.all_tasks(event_loop):
                coro = task.get_coro()
                output_file.write(repr(task) + "\n")
                output_file.write(repr(coro) + "\n")
                output_file.write(repr(task.get_stack()) + "\n")

                # See https://docs.python.org/3/library/inspect.html#types-and-members
                # for more info on these attributes.
                while coro is not None:
                    cr_code = getattr(coro, "cr_code", None)
                    cr_frame = getattr(coro, "cr_frame", None)
                    if cr_code and cr_frame:
                        output_file.write(
                            f"\tcr_code={cr_code!r}, cr_frame={cr_frame!r}\n"
                        )
                        coro = getattr(coro, "cr_await", None)
                        continue
                    ag_code = getattr(coro, "ag_code", None)
                    ag_frame = getattr(coro, "ag_frame", None)
                    if ag_code and ag_frame:
                        output_file.write(
                            f"\tag_code={ag_code!r}, ag_frame={ag_frame!r}\n"
                        )
                        coro = getattr(coro, "ag_await", None)
                        continue
                    output_file.write("done\n")
                    break
                output_file.write("\n")
        logging.warning("XXX: dump_tasks: done")
    except:
        logging.exception("XXX: dump_tasks: failed to collect")
        raise
