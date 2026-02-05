import argparse
from colorama import init
from utils.pe_parser import parse_pe
from utils.formatter import color_flag, human_size

init()

def print_report(report):
    print("\n========== PE ANALYZER REPORT ==========\n")
    print(f"[+] File: {report['file_path']}")
    print(f"[+] Machine: {report['machine']}")
    print(f"[+] Sections: {report['number_of_sections']}")
    print(f"[+] Entry Point: {report['entry_point']}")
    print(f"[+] Image Base: {report['image_base']}")
    print(f"[+] Compile Time (UTC): {report['compile_time']}")

    print("\n========== SECTIONS ==========\n")
    for sec in report["sections"]:
        suspicious_entropy = sec["entropy"] > 7.2
        rwx = sec["is_readable"] and sec["is_writable"] and sec["is_executable"]

        print(f"Section: {sec['name']}")
        print(f"  VA: {sec['virtual_address']}")
        print(f"  VSIZE: {human_size(sec['virtual_size'])}")
        print(f"  RSIZE: {human_size(sec['raw_size'])}")
        print(f"  Entropy: {color_flag(str(sec['entropy']), suspicious_entropy)}")
        print(f"  Readable: {sec['is_readable']}")
        print(f"  Writable: {sec['is_writable']}")
        print(f"  Executable: {sec['is_executable']}")
        if rwx:
            print(color_flag("  ⚠ RWX Section Detected!", True))
        print()

    print("\n========== IMPORTS ==========\n")
    if report["imports"]:
        for dll, funcs in report["imports"].items():
            print(f"{dll} ({len(funcs)} functions)")
            for f in funcs[:15]:
                print(f"   - {f}")
            if len(funcs) > 15:
                print("   ...")
            print()
    else:
        print("No imports found (possible packing / manual API resolving).")

    print("\n========== EXPORTS ==========\n")
    if report["exports"]:
        for e in report["exports"]:
            print(f" - {e}")
    else:
        print("No exports found.")

    print("\n========== PACKING HINTS ==========\n")
    packed_suspect = False
    for sec in report["sections"]:
        if sec["entropy"] > 7.2:
            packed_suspect = True

    if not report["imports"] or packed_suspect:
        print(color_flag("⚠ Possible packed or obfuscated binary detected!", True))
    else:
        print(color_flag("No strong packing indicators detected.", False))

    print("\n=======================================\n")

def main():
    parser = argparse.ArgumentParser(description="Simple PE Analyzer Tool")
    parser.add_argument("file", help="Path to PE file (.exe/.dll)")
    args = parser.parse_args()

    report = parse_pe(args.file)
    print_report(report)

if __name__ == "__main__":
    main()
