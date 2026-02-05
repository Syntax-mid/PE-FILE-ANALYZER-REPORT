import pefile
import datetime
from utils.entropy import calculate_entropy

def parse_pe(file_path):
    pe = pefile.PE(file_path)

    report = {}
    report["file_path"] = file_path
    report["machine"] = hex(pe.FILE_HEADER.Machine)
    report["number_of_sections"] = pe.FILE_HEADER.NumberOfSections
    report["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    report["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)

    # Compile timestamp
    ts = pe.FILE_HEADER.TimeDateStamp
    report["compile_time"] = str(datetime.datetime.utcfromtimestamp(ts))

    # Sections
    sections = []
    for sec in pe.sections:
        sec_name = sec.Name.decode(errors="ignore").strip("\x00")
        sec_data = sec.get_data()
        entropy = calculate_entropy(sec_data)

        sections.append({
            "name": sec_name,
            "virtual_address": hex(sec.VirtualAddress),
            "virtual_size": sec.Misc_VirtualSize,
            "raw_size": sec.SizeOfRawData,
            "entropy": round(entropy, 2),
            "characteristics": hex(sec.Characteristics),
            "is_executable": bool(sec.Characteristics & 0x20000000),
            "is_writable": bool(sec.Characteristics & 0x80000000),
            "is_readable": bool(sec.Characteristics & 0x40000000),
        })

    report["sections"] = sections

    # Imports
    imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode(errors="ignore"))
                else:
                    funcs.append(f"Ordinal_{imp.ordinal}")
            imports[dll_name] = funcs

    report["imports"] = imports

    # Exports
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode(errors="ignore"))
            else:
                exports.append(f"Ordinal_{exp.ordinal}")

    report["exports"] = exports

    return report
