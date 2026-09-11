"""PE and ELF binary parser for static analysis."""

import struct
from typing import Dict, Any, List, Optional, Tuple


class BinaryParseError(Exception):
    pass


class PEParser:
    """Pure-Python PE32 / PE32+ (EXE/DLL/SYS) header and structure parser."""

    IMAGE_FILE_MACHINE_I386 = 0x014c
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64

    def __init__(self, data: bytes):
        self.data = data
        self.dos_header: Dict[str, Any] = {}
        self.nt_headers: Dict[str, Any] = {}
        self.file_header: Dict[str, Any] = {}
        self.optional_header: Dict[str, Any] = {}
        self.sections: List[Dict[str, Any]] = []
        self.imports: Dict[str, List[str]] = {}
        self.exports: List[Dict[str, Any]] = []
        self.is_64bit = False
        self._parse()

    def _parse(self) -> None:
        if len(self.data) < 64:
            raise BinaryParseError("File is too small to contain a DOS header")

        magic = self.data[:2]
        if magic != b"MZ":
            raise BinaryParseError(f"Invalid DOS magic: {magic!r}")

        (e_lfanew,) = struct.unpack_from("<I", self.data, 0x3C)
        self.dos_header = {"e_magic": "MZ", "e_lfanew": e_lfanew}

        if e_lfanew + 4 > len(self.data):
            raise BinaryParseError("Invalid e_lfanew offset beyond file bounds")

        pe_sig = self.data[e_lfanew : e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            raise BinaryParseError(f"Invalid PE signature: {pe_sig!r}")

        file_header_offset = e_lfanew + 4
        if file_header_offset + 20 > len(self.data):
            raise BinaryParseError("PE file header truncated")

        (
            machine,
            num_sections,
            time_stamp,
            sym_table,
            num_symbols,
            size_opt_header,
            characteristics,
        ) = struct.unpack_from("<HHIIIHH", self.data, file_header_offset)

        self.file_header = {
            "Machine": hex(machine),
            "MachineName": self._get_machine_name(machine),
            "NumberOfSections": num_sections,
            "TimeDateStamp": time_stamp,
            "SizeOfOptionalHeader": size_opt_header,
            "Characteristics": hex(characteristics),
        }

        opt_header_offset = file_header_offset + 20
        if size_opt_header > 0 and opt_header_offset + 2 <= len(self.data):
            (opt_magic,) = struct.unpack_from("<H", self.data, opt_header_offset)
            self.is_64bit = opt_magic == 0x020B

            if self.is_64bit:
                self._parse_optional_header_64(opt_header_offset)
            else:
                self._parse_optional_header_32(opt_header_offset)

        section_offset = opt_header_offset + size_opt_header
        for i in range(num_sections):
            if section_offset + 40 > len(self.data):
                break
            sec = self._parse_section_header(section_offset)
            self.sections.append(sec)
            section_offset += 40

        self._parse_imports()
        self._parse_exports()

    def _get_machine_name(self, machine: int) -> str:
        if machine == self.IMAGE_FILE_MACHINE_AMD64:
            return "x64 (AMD64)"
        if machine == self.IMAGE_FILE_MACHINE_I386:
            return "x86 (i386)"
        if machine == self.IMAGE_FILE_MACHINE_ARM64:
            return "ARM64"
        return f"Unknown (0x{machine:04x})"

    def _parse_optional_header_32(self, offset: int) -> None:
        if offset + 96 > len(self.data):
            return
        (
            magic,
            major_linker,
            minor_linker,
            size_code,
            size_init_data,
            size_uninit_data,
            entrypoint,
            base_of_code,
            base_of_data,
            image_base,
            section_alignment,
            file_alignment,
            major_os,
            minor_os,
            major_image,
            minor_image,
            major_subsys,
            minor_subsys,
            win32_version,
            size_image,
            size_headers,
            checksum,
            subsystem,
            dll_char,
            size_stack_reserve,
            size_stack_commit,
            size_heap_reserve,
            size_heap_commit,
            loader_flags,
            num_rva_sizes,
        ) = struct.unpack_from("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", self.data, offset)  # PE32: 9 dwords through FileAlignment

        self.optional_header = {
            "Magic": "PE32",
            "AddressOfEntryPoint": hex(entrypoint),
            "EntryPoint": entrypoint,
            "ImageBase": hex(image_base),
            "SectionAlignment": section_alignment,
            "FileAlignment": file_alignment,
            "SizeOfImage": size_image,
            "Subsystem": subsystem,
            "NumberOfRvaAndSizes": num_rva_sizes,
        }
        self._parse_data_directories(offset + 96, num_rva_sizes)

    def _parse_optional_header_64(self, offset: int) -> None:
        if offset + 112 > len(self.data):
            return
        (
            magic,
            major_linker,
            minor_linker,
            size_code,
            size_init_data,
            size_uninit_data,
            entrypoint,
            base_of_code,
            image_base,
            section_alignment,
            file_alignment,
            major_os,
            minor_os,
            major_image,
            minor_image,
            major_subsys,
            minor_subsys,
            win32_version,
            size_image,
            size_headers,
            checksum,
            subsystem,
            dll_char,
            size_stack_reserve,
            size_stack_commit,
            size_heap_reserve,
            size_heap_commit,
            loader_flags,
            num_rva_sizes,
        ) = struct.unpack_from("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", self.data, offset)  # PE32+: BaseOfCode is 4 bytes, ImageBase 8

        self.optional_header = {
            "Magic": "PE32+",
            "AddressOfEntryPoint": hex(entrypoint),
            "EntryPoint": entrypoint,
            "ImageBase": hex(image_base),
            "SectionAlignment": section_alignment,
            "FileAlignment": file_alignment,
            "SizeOfImage": size_image,
            "Subsystem": subsystem,
            "NumberOfRvaAndSizes": num_rva_sizes,
        }
        self._parse_data_directories(offset + 112, num_rva_sizes)

    def _parse_data_directories(self, offset: int, count: int) -> None:
        names = [
            "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
            "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
            "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR_RUNTIME"
        ]
        self.data_directories: Dict[str, Tuple[int, int]] = {}
        for i in range(min(count, len(names))):
            if offset + 8 > len(self.data):
                break
            rva, size = struct.unpack_from("<II", self.data, offset)
            if rva != 0 or size != 0:
                self.data_directories[names[i]] = (rva, size)
            offset += 8

    def _parse_section_header(self, offset: int) -> Dict[str, Any]:
        raw_name = self.data[offset : offset + 8].rstrip(b"\x00")
        name = raw_name.decode("latin1", errors="replace")
        (
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_reloc,
            pointer_to_lineno,
            num_reloc,
            num_lineno,
            characteristics,
        ) = struct.unpack_from("<IIIIIIHHI", self.data, offset + 8)

        return {
            "Name": name,
            "VirtualSize": virtual_size,
            "VirtualAddress": hex(virtual_address),
            "RVA": virtual_address,
            "SizeOfRawData": size_of_raw_data,
            "PointerToRawData": pointer_to_raw_data,
            "Characteristics": hex(characteristics),
        }

    def rva_to_offset(self, rva: int) -> Optional[int]:
        for sec in self.sections:
            sec_rva = sec["RVA"]
            sec_vsize = sec["VirtualSize"] or sec["SizeOfRawData"]
            sec_raw = sec["PointerToRawData"]
            if sec_rva <= rva < sec_rva + sec_vsize:
                return sec_raw + (rva - sec_rva)
        return None

    def _read_cstring(self, offset: int, max_len: int = 256) -> str:
        end = self.data.find(b"\x00", offset, offset + max_len)
        if end == -1:
            end = offset + max_len
        return self.data[offset:end].decode("latin1", errors="replace")

    def _parse_imports(self) -> None:
        if not hasattr(self, "data_directories") or "IMPORT" not in self.data_directories:
            return
        rva, size = self.data_directories["IMPORT"]
        offset = self.rva_to_offset(rva)
        if offset is None:
            return

        while offset + 20 <= len(self.data):
            (
                original_first_thunk,
                time_stamp,
                forwarder_chain,
                name_rva,
                first_thunk,
            ) = struct.unpack_from("<IIIII", self.data, offset)

            if original_first_thunk == 0 and first_thunk == 0 and name_rva == 0:
                break

            dll_name_offset = self.rva_to_offset(name_rva)
            if dll_name_offset is not None:
                dll_name = self._read_cstring(dll_name_offset)
                self.imports[dll_name] = []
                thunk_rva = original_first_thunk if original_first_thunk else first_thunk
                thunk_offset = self.rva_to_offset(thunk_rva)
                if thunk_offset is not None:
                    step = 8 if self.is_64bit else 4
                    mask = 0x8000000000000000 if self.is_64bit else 0x80000000
                    fmt = "<Q" if self.is_64bit else "<I"
                    while thunk_offset + step <= len(self.data):
                        (val,) = struct.unpack_from(fmt, self.data, thunk_offset)
                        if val == 0:
                            break
                        if val & mask:
                            ordinal = val & 0xFFFF
                            self.imports[dll_name].append(f"Ordinal_{ordinal}")
                        else:
                            name_data_offset = self.rva_to_offset(val)
                            if name_data_offset is not None and name_data_offset + 2 <= len(self.data):
                                fn_name = self._read_cstring(name_data_offset + 2)
                                self.imports[dll_name].append(fn_name)
                        thunk_offset += step
            offset += 20

    def _parse_exports(self) -> None:
        if not hasattr(self, "data_directories") or "EXPORT" not in self.data_directories:
            return
        rva, size = self.data_directories["EXPORT"]
        offset = self.rva_to_offset(rva)
        if offset is None or offset + 40 > len(self.data):
            return

        (
            flags,
            time_stamp,
            major_ver,
            minor_ver,
            name_rva,
            ordinal_base,
            num_functions,
            num_names,
            addr_functions,
            addr_names,
            addr_ordinals,
        ) = struct.unpack_from("<IIHHIIIIIII", self.data, offset)

        names_offset = self.rva_to_offset(addr_names)
        ordinals_offset = self.rva_to_offset(addr_ordinals)
        functions_offset = self.rva_to_offset(addr_functions)

        if names_offset and ordinals_offset and functions_offset:
            for i in range(num_names):
                # Bounds must be checked per-iteration: the tables may be truncated
                # mid-way, so a large num_names must not walk off the end of the file.
                if (
                    names_offset + i * 4 + 4 > len(self.data)
                    or ordinals_offset + i * 2 + 2 > len(self.data)
                ):
                    break
                (n_rva,) = struct.unpack_from("<I", self.data, names_offset + i * 4)
                (ord_idx,) = struct.unpack_from("<H", self.data, ordinals_offset + i * 2)
                fn_name_offset = self.rva_to_offset(n_rva)
                fn_name = self._read_cstring(fn_name_offset) if fn_name_offset else f"Export_{i}"

                fn_rva = 0
                if functions_offset + ord_idx * 4 + 4 <= len(self.data):
                    (fn_rva,) = struct.unpack_from("<I", self.data, functions_offset + ord_idx * 4)

                self.exports.append({
                    "name": fn_name,
                    "ordinal": ordinal_base + ord_idx,
                    "rva": hex(fn_rva),
                })

    def summary(self) -> Dict[str, Any]:
        return {
            "format": "PE",
            "is_64bit": self.is_64bit,
            "machine": self.file_header.get("MachineName"),
            "entrypoint": self.optional_header.get("AddressOfEntryPoint"),
            "image_base": self.optional_header.get("ImageBase"),
            "sections": [s["Name"] for s in self.sections],
            "imported_dlls": list(self.imports.keys()),
            "export_count": len(self.exports),
        }
