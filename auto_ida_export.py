import idc
import ida_auto
import ida_nalt
import ida_hexrays
import idaapi
import os

def get_out_dir():
    # IDA passes args via idc.ARGV
    argv = getattr(idc, "ARGV", [])
    print("[AUTO] idc.ARGV =", argv)

    if "--out" in argv:
        i = argv.index("--out")
        if i + 1 < len(argv):
            return argv[i + 1]

    return None


def main():
    print("[AUTO] Script started")

    # Wait for analysis
    ida_auto.auto_wait()

    out_root = get_out_dir()
    if not out_root:
        print("[AUTO] ERROR: --out not provided")
        idc.qexit(1)

    in_path = ida_nalt.get_input_file_path()
    base = os.path.basename(in_path)
    base_noext = os.path.splitext(base)[0]

    export_dir = os.path.join(out_root, f"{base_noext}_export")
    os.makedirs(export_dir, exist_ok=True)

    print("[AUTO] Export dir:", export_dir)

    # Import your plugin
    sys_path_plugins = idaapi.idadir("plugins")
    if sys_path_plugins not in sys.path:
        sys.path.insert(0, sys_path_plugins)

    import FuncExporter as FE

    has_hexrays = ida_hexrays.init_hexrays_plugin()

    FE.export_strings(export_dir)
    FE.export_imports(export_dir)
    FE.export_exports(export_dir)
    FE.export_call_graph(export_dir)
    FE.export_memory(export_dir)
    FE.export_functions_json(export_dir)
    
    if has_hexrays:
        FE.export_decompiled_functions(export_dir)

    print("[AUTO] Finished")
    idc.qexit(0)


if __name__ == "__main__":
    main()