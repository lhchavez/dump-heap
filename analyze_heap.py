import argparse
import collections
import dataclasses
import copy
import gzip
import io
import logging

import msgpack


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


def _scanheap(filename: str, populate_referrers: bool = True) -> dict[int, HeapObject]:
    typenames: dict[int, str] = {}
    live_objects: dict[int, HeapObject] = {}
    logging.info("%s: scanning live objects...", filename)
    file: io.IOBase
    if filename.endswith(".gz"):
        file = gzip.open(filename, "rb")
    else:
        file = open(filename, "rb")
    with file as f:
        for record in msgpack.Unpacker(f):
            if record["t"] == "done":
                break
            elif record["t"] == "type":
                typenames[record["objtype_addr"]] = record["typename"]
            elif record["t"] == "object":
                payload_bytes = record.get("payload", None)
                payload: str | None = None
                if payload_bytes is not None:
                    payload = payload_bytes.decode("utf-8", "replace")
                live_objects[record["addr"]] = HeapObject(
                    addr=record["addr"],
                    typename=typenames[record["objtype_addr"]],
                    size=record["size"],
                    root=record["root"],
                    payload=payload,
                )
            elif record["t"] == "referents":
                referents = live_objects[record["addr"]].referents
                referents.clear()
                referents.update(record["child_addrs"])
            else:
                logging.fatal("unknown record kind %d", record["t"])
        else:
            logging.warning("incomplete file")
    logging.info("%s: %d live objects scanned", filename, len(live_objects))
    # Now that we have the full graph, fill in the referrers, which is the
    # transpose graph of the referents.
    if populate_referrers:
        for obj in live_objects.values():
            for referent in obj.referents:
                live_objects[referent].referrers.add(obj.addr)
    return live_objects


def _main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--remove-heap-dump",
        default=None,
        help="A previous heap dump. Only live objects that do not appear in the previous heap dump will be considered.",
    )
    parser.add_argument(
        "--intersect-heap-dump",
        default=None,
        help="A future heap dump. Only live objects that also appear in the future heap dump will be considered.",
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
        addresses: set[int] | None = None
        excluded_addresses: set[int] | None = None
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
            if addresses is not None and excluded_addresses is not None:
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

            if not obj.referrers:
                continue
            if depth >= args.max_depth:
                print(
                    f'  x{obj.addr:x}_parents [label="...",shape=circle,style=filled,fillcolor=gray];'
                )
                print(f"  x{obj.addr:x} -> x{obj.addr:x}_parents [style=dotted];")
                continue
            if obj.referrers and len(obj.referrers) >= args.max_breadth:
                print(
                    f'  x{obj.addr:x}_parents [label="...{len(obj.referrers)}...",shape=oval,style=filled,fillcolor=gray];'
                )
                print(f"  x{obj.addr:x} -> x{obj.addr:x}_parents [style=dotted];")
                continue
            if obj.typename not in {
                "builtins.function",
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
    parser_graph.add_argument(
        "--max-breadth",
        default=20,
        type=int,
        help="The maximum number of nodes to expand when traversing parents / children.",
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

    all_objects = _scanheap(args.heap_dump)
    live_objects = all_objects

    if args.intersect_heap_dump is not None:
        intersect_objects = _scanheap(
            args.intersect_heap_dump, populate_referrers=False
        )
        # Keep all objects that have survived between the heap dumps.
        previous_live_objects = copy.copy(live_objects)
        live_objects = {}
        for addr, live_obj in previous_live_objects.items():
            if addr not in intersect_objects:
                continue
            intersect_obj = intersect_objects[addr]
            if (
                intersect_obj.size != live_obj.size
                or intersect_obj.typename != live_obj.typename
            ):
                continue
            live_objects[addr] = live_obj
    if args.remove_heap_dump is not None:
        remove_objects = _scanheap(args.remove_heap_dump, populate_referrers=False)
        # Remove any objects present in the other heap dump.
        previous_live_objects = copy.copy(live_objects)
        live_objects = {}
        for addr, live_obj in previous_live_objects.items():
            if addr in remove_objects:
                continue
            live_objects[addr] = live_obj

    args.func(args)


if __name__ == "__main__":
    _main()
