import argparse
import collections
import dataclasses
import copy
import gzip
import logging
import struct
from typing import NamedTuple

RECORD_DONE = 0
RECORD_TYPE = 1
RECORD_OBJECT = 2
RECORD_OBJECT_WITH_PAYLOAD = 3
RECORD_REFERENTS = 4


@dataclasses.dataclass(order=True)
class HeapObject:
    # Keep size first so that we can sort a list by size easily.
    size: int
    addr: int
    typename: str
    root: bool
    children_size_exclusive: int = 0
    # Pointers from this object to other objects.
    referents: set[int] = dataclasses.field(default_factory=set)
    # Back-pointers from other objects to this object.
    referrers: set[int] = dataclasses.field(default_factory=set)
    payload: str | None = None


def _scanheap(filename: str) -> dict[int, HeapObject]:
    typenames: dict[int, str] = {}
    live_objects: dict[int, HeapObject] = {}
    logging.info("%s: scanning live objects...", filename)
    if filename.endswith(".gz"):
        file = gzip.open(filename, "rb")
    else:
        file = open(filename, "rb")
    with file as f:
        while True:
            (record_kind,) = struct.unpack("B", f.read(1))
            if record_kind == RECORD_DONE:
                # !B
                break
            elif record_kind == RECORD_TYPE:
                # !BQH{len(typename)}s
                objtype_addr, objtype_len = struct.unpack("!QH", f.read(10))
                typenames[objtype_addr] = f.read(objtype_len).decode("utf-8")
            elif record_kind == RECORD_OBJECT:
                # !B?QQL
                root, addr, objtype_addr, size = struct.unpack("!?QQL", f.read(21))
                live_objects[addr] = HeapObject(
                    addr=addr,
                    typename=typenames[objtype_addr],
                    size=size,
                    root=root,
                )
            elif record_kind == RECORD_OBJECT_WITH_PAYLOAD:
                # !B?QQLH{len(payload)}s
                root, addr, objtype_addr, size, payload_len = struct.unpack(
                    "!?QQLH", f.read(23)
                )
                payload = f.read(payload_len).decode("utf-8", "replace")
                live_objects[addr] = HeapObject(
                    addr=addr,
                    typename=typenames[objtype_addr],
                    size=size,
                    payload=payload,
                    root=root,
                )
            elif record_kind == RECORD_REFERENTS:
                # !BQH{len(referents)}Q
                addr, referents_len = struct.unpack("!QH", f.read(10))
                referents = live_objects[addr].referents
                referents.clear()
                referents.update(
                    struct.unpack(
                        f"{referents_len}Q",
                        f.read(8 * referents_len),
                    )
                )
            else:
                logging.fatal("unknown record kind %d", record_kind)
        else:
            logging.warning("incomplete file")
    logging.info("%s: %d live objects scanned", filename, len(live_objects))
    # Now that we have the full graph, fill in the referrers, which is the
    # transpose graph of the referents.
    for obj in live_objects.values():
        for referent in obj.referents:
            live_objects[referent].referrers.add(obj.addr)
    return live_objects


def _main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--previous-heap-dump",
        default=None,
        help="A previous heap dump. Only live objects that also appear in the previous heap dump will be considered.",
    )
    subparsers = parser.add_subparsers()

    def _top(args: argparse.Namespace) -> None:
        entries_shown = 0
        logging.info("sorting entries...")

        for obj in sorted(live_objects.values(), reverse=True):
            if entries_shown > args.top_allocations:
                break
            if args.filter and args.filter not in obj.typename:
                continue
            entries_shown += 1
            print(
                f"- {obj.size:8d} {obj.addr:016x} {obj.typename} "
                + (repr(obj.payload) if obj.payload is not None else "")
                + (" (root)" if obj.root else ""),
            )
            if args.show_parents:
                seen = set()
                queue = [(1, addr) for addr in obj.referrers]
                while queue:
                    depth, addr = queue.pop()
                    child_obj = all_objects[addr]
                    print(
                        f'{"  " * depth + "- "}{child_obj.size:8d} '
                        f'{child_obj.addr:016x} {child_obj.typename} '
                        + (
                            repr(child_obj.payload)
                            if child_obj.payload is not None
                            else ""
                        )
                        + (" (cycle)" if addr in seen else "")
                        + (" (root)" if child_obj.root else ""),
                    )
                    if addr in seen:
                        continue
                    seen.add(addr)
                    if depth >= args.max_depth:
                        print(f'{"  " * (depth + 1) + "- "} ...')
                        continue
                    queue.extend((depth + 1, addr) for addr in child_obj.referrers)
                print("=" * 80)

    parser_top = subparsers.add_parser("top", help="Show the top heap objects")
    parser_top.add_argument(
        "--top-allocations",
        default=50,
        type=int,
        help="How many of the biggest allocations to show",
    )
    parser_top.add_argument(
        "--filter",
        type=str,
        help="Filter entries by typename.",
    )
    parser_top.add_argument(
        "--show-parents",
        action="store_true",
        help="Whether to show the parents of the biggest allocations",
    )
    parser_top.add_argument(
        "--max-depth",
        default=10,
        type=int,
        help="The maximum depth to show when traversing parents.",
    )
    parser_top.add_argument("heap_dump", metavar="heap-dump")
    parser_top.set_defaults(func=_top)

    def _graph(args: argparse.Namespace) -> None:
        queue: list[tuple[int, HeapObject]] = []
        seen: set[int] = set()
        ranks = collections.defaultdict[int, list[int]](list)
        addresses: Optional[set[int]] = None
        excluded_addresses: Optional[set[int]] = None
        if "0x" in args.filter:
            filter_exprs = args.filter.split(",")
            excluded_addresses = set(
                int(x.strip("!"), 16) for x in filter_exprs if x.startswith("!")
            )
            addresses = set(int(x, 16) for x in filter_exprs if not x.startswith("!"))
        print("digraph heap {")
        print(
            f'  label="Heap visualization of {args.heap_dump}, generated with https://github.com/lhchavez/dump-heap";'
        )
        print("  rankdir=TB;")
        print("  node [shape=box];")
        print("  edge [dir=back];")
        for obj in live_objects.values():
            if addresses is not None:
                if obj.addr not in addresses or obj.addr in excluded_addresses:
                    continue
            elif args.filter not in obj.typename:
                continue
            queue.append((0, obj))
        while queue:
            depth, obj = queue.pop(0)
            if obj.addr in seen:
                continue
            seen.add(obj.addr)
            ranks[depth].append(obj.addr)

            style = ""
            if excluded_addresses is not None and obj.addr in excluded_addresses:
                style = ",style=filled,fillcolor=gray"
            elif depth == 0:
                style = ",style=filled,fillcolor=red"
            elif args.highlight and args.highlight in obj.typename:
                style = ",style=filled,fillcolor=yellow"
            payload = ""
            if obj.payload is not None:
                if len(payload) <= 32:
                    payload = f"\\n{obj.payload}"
                else:
                    payload = f"\\n{obj.payload[:31]}…"
            print(
                f'  x{obj.addr:x} [label="0x{obj.addr:x}\\n{obj.typename}\\n{obj.size}{payload}"{style}];'
            )
            if excluded_addresses is not None and obj.addr in excluded_addresses:
                continue

            if depth >= args.max_depth:
                if obj.referrers:
                    print(f'  x{obj.addr:x}_parents [label="...",shape=circle];')
                    print(f"  x{obj.addr:x} -> x{obj.addr:x}_parents [style=dotted];")
                continue
            if obj.typename not in {
                "builtins.type",
                "builtins.function",
                "builtins.module",
            }:
                for addr in obj.referrers:
                    referrer_obj = all_objects[addr]
                    style = ""
                    if addr in seen:
                        style = " [style=dashed]"
                    elif len(referrer_obj.referents) == 1:
                        # Marking any single references with bold arrows.
                        style = " [style=bold]"
                    print(f"  x{obj.addr:x} -> x{addr:x}{style};")
                    queue.append((depth + 1, referrer_obj))
        for rank in range(args.max_depth + 1):
            if rank not in ranks:
                break
            addrs = ranks[rank]
            print(
                "  { rank="
                + ("source" if rank == 0 else "same")
                + "; "
                + "; ".join(f"x{addr:x}" for addr in addrs)
                + "; };"
            )
        print("}")
        pass

    parser_graph = subparsers.add_parser(
        "graph", help="Create a graphviz graph centered on specific types"
    )
    parser_graph.add_argument(
        "--max-depth",
        default=1,
        type=int,
        help="The maximum depth to show when traversing parents / children.",
    )
    parser_graph.add_argument("heap_dump", metavar="heap-dump")
    parser_graph.add_argument(
        "--filter",
        type=str,
        help="Filter entries by typename or address",
        required=True,
    )
    parser_graph.add_argument(
        "--highlight",
        type=str,
        help="Highlight entries by typename.",
    )
    parser_graph.set_defaults(func=_graph)
    args = parser.parse_args()

    live_objects = _scanheap(args.heap_dump)
    all_objects = copy.copy(live_objects)

    if args.previous_heap_dump is not None:
        previous_objects = _scanheap(args.previous_heap_dump)
        # Keep all objects that have survived between the heap dumps.
        live_objects: dict[int, HeapObjects] = {}
        for addr in set(all_objects.keys()) & set(previous_objects.keys()):
            previous_obj = previous_objects[addr]
            live_obj = all_objects[addr]
            if (
                previous_obj.size != live_obj.size
                or previous_obj.typename != live_obj.typename
            ):
                continue
            live_objects[addr] = live_obj

    args.func(args)


if __name__ == "__main__":
    _main()
