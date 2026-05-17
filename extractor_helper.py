import os
from pe_extractor import PEFeatureExtractor
import re
import math
import numpy as np
import pefile

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    # Count byte occurrences
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def get_strings_features(data):
    # Regex for printable ASCII strings (length >= 4)
    string_regex = re.compile(rb'[\x20-\x7E]{4,}')
    strings = string_regex.findall(data)
    
    numstrings = len(strings)
    if numstrings == 0:
        return {
            'numstrings': 0,
            'avlength': 0.0,
            'printables': 0,
            'printabledist': [0] * 96,
            'entropy': 0.0,
            'paths': 0,
            'urls': 0,
            'registry': 0,
            'MZ': 0
        }
    
    lengths = [len(s) for s in strings]
    avlength = float(np.mean(lengths))
    printables = int(np.sum(lengths))
    
    # Calculate printable char distribution (ASCII 32 to 127)
    all_chars = b"".join(strings)
    char_counts = np.bincount(np.frombuffer(all_chars, dtype=np.uint8), minlength=256)
    printabledist = list(char_counts[32:128])
    
    # Simple Shannon entropy of the string character distribution
    entropy = calculate_entropy(all_chars)
    
    # Search for patterns
    decoded_strings = []
    for s in strings:
        try:
            decoded_strings.append(s.decode('ascii', errors='ignore'))
        except Exception:
            pass
            
    paths = sum(1 for s in decoded_strings if re.search(r'[a-zA-Z]:\\', s) or '\\\\' in s)
    urls = sum(1 for s in decoded_strings if 'http://' in s.lower() or 'https://' in s.lower() or 'www.' in s.lower())
    registry = sum(1 for s in decoded_strings if 'hkey_' in s.lower())
    mz = data.count(b'MZ')
    
    return {
        'numstrings': numstrings,
        'avlength': avlength,
        'printables': printables,
        'printabledist': printabledist,
        'entropy': entropy,
        'paths': paths,
        'urls': urls,
        'registry': registry,
        'MZ': mz
    }

def extract_raw_pe_features(file_path):
    # 1. Read raw file bytes
    with open(file_path, 'rb') as f:
        data = f.read()
        
    file_size = len(data)
    
    # 2. Compute byte histogram (256 counts)
    hist = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    histogram = list(hist)
    
    # 3. Compute simplified byte entropy histogram (size 256)
    # For compatibility, we'll split the file into 1024-byte chunks, calculate entropy for each,
    # and map them into 256 bins based on byte-entropy distribution
    byteentropy = [0] * 256
    chunk_size = 1024
    if file_size > 0:
        for i in range(0, file_size, chunk_size):
            chunk = data[i:i+chunk_size]
            ent = calculate_entropy(chunk)
            # Map entropy (0.0 to 8.0) into 256 indices (0 to 255)
            ent_idx = min(255, int(ent * 32))
            # Distribute counts
            for b in chunk:
                byteentropy[ent_idx] += 1
                
    # Normalize byteentropy to counts
    byteentropy = list(np.clip(byteentropy, 0, None))
    
    # 4. Extract strings
    strings = get_strings_features(data)
    
    # 5. Parse PE structure using pefile
    pe = pefile.PE(file_path)
    
    # General file info
    vsize = pe.OPTIONAL_HEADER.SizeOfImage if pe.OPTIONAL_HEADER else 0
    has_debug = 1 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0
    exports_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
    
    imports_count = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports_count += len(entry.imports)
            
    has_reloc = 1 if pe.OPTIONAL_HEADER and pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']].Size > 0 else 0
    has_res = 1 if pe.OPTIONAL_HEADER and pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size > 0 else 0
    has_sig = 1 if pe.OPTIONAL_HEADER and pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size > 0 else 0
    has_tls = 1 if pe.OPTIONAL_HEADER and pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']].Size > 0 else 0
    symbols_count = pe.FILE_HEADER.NumberOfSymbols if pe.FILE_HEADER else 0
    
    general = {
        'size': file_size,
        'vsize': vsize,
        'has_debug': has_debug,
        'exports': exports_count,
        'imports': imports_count,
        'has_relocations': has_reloc,
        'has_resources': has_res,
        'has_signature': has_sig,
        'has_tls': has_tls,
        'symbols': symbols_count
    }
    
    # Header File Info
    timestamp = pe.FILE_HEADER.TimeDateStamp if pe.FILE_HEADER else 0
    machine_val = pe.FILE_HEADER.Machine if pe.FILE_HEADER else 0
    machine = pefile.MACHINE_TYPE.get(machine_val, 'IMAGE_FILE_MACHINE_UNKNOWN')
    
    char_list = []
    if pe.FILE_HEADER:
        for flag, char_name in pefile.IMAGE_CHARACTERISTICS.items():
            if isinstance(flag, int):
                if pe.FILE_HEADER.Characteristics & flag:
                    char_list.append(char_name)
                
    subsystem_val = pe.OPTIONAL_HEADER.Subsystem if pe.OPTIONAL_HEADER else 0
    subsystem = pefile.SUBSYSTEM_TYPE.get(subsystem_val, 'IMAGE_SUBSYSTEM_UNKNOWN')
    
    dll_caps = []
    if pe.OPTIONAL_HEADER:
        for flag, cap_name in pefile.DLL_CHARACTERISTICS.items():
            if isinstance(flag, int):
                if pe.OPTIONAL_HEADER.DllCharacteristics & flag:
                    dll_caps.append(cap_name)
                
    magic_val = pe.OPTIONAL_HEADER.Magic if pe.OPTIONAL_HEADER else 0
    magic = 'PE32' if magic_val == 0x10b else ('PE32+' if magic_val == 0x20b else 'UNKNOWN')
    
    opt_headers = {
        'major_image_version': pe.OPTIONAL_HEADER.MajorImageVersion if pe.OPTIONAL_HEADER else 0,
        'minor_image_version': pe.OPTIONAL_HEADER.MinorImageVersion if pe.OPTIONAL_HEADER else 0,
        'major_linker_version': pe.OPTIONAL_HEADER.MajorLinkerVersion if pe.OPTIONAL_HEADER else 0,
        'minor_linker_version': pe.OPTIONAL_HEADER.MinorLinkerVersion if pe.OPTIONAL_HEADER else 0,
        'major_operating_system_version': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion if pe.OPTIONAL_HEADER else 0,
        'minor_operating_system_version': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion if pe.OPTIONAL_HEADER else 0,
        'major_subsystem_version': pe.OPTIONAL_HEADER.MajorSubsystemVersion if pe.OPTIONAL_HEADER else 0,
        'minor_subsystem_version': pe.OPTIONAL_HEADER.MinorSubsystemVersion if pe.OPTIONAL_HEADER else 0,
        'sizeof_code': pe.OPTIONAL_HEADER.SizeOfCode if pe.OPTIONAL_HEADER else 0,
        'sizeof_headers': pe.OPTIONAL_HEADER.SizeOfHeaders if pe.OPTIONAL_HEADER else 0,
        'sizeof_heap_commit': pe.OPTIONAL_HEADER.SizeOfHeapCommit if pe.OPTIONAL_HEADER else 0
    }
    
    header = {
        'coff': {
            'timestamp': timestamp,
            'machine': machine,
            'characteristics': char_list
        },
        'optional': {
            'subsystem': subsystem,
            'dll_characteristics': dll_caps,
            'magic': magic,
            **opt_headers
        }
    }
    
    # Section Info
    sections_list = []
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint if pe.OPTIONAL_HEADER else 0
    entry_section_name = ""
    
    for sect in pe.sections:
        name = sect.Name.decode('utf-8', errors='ignore').strip('\x00')
        sect_data = sect.get_data()
        sect_entropy = calculate_entropy(sect_data)
        
        # Props
        props = []
        for flag, char_name in pefile.SECTION_CHARACTERISTICS.items():
            if isinstance(flag, int):
                if sect.Characteristics & flag:
                    props.append(char_name)
                
        sections_list.append({
            'name': name,
            'size': sect.SizeOfRawData,
            'entropy': sect_entropy,
            'vsize': sect.Misc_VirtualSize,
            'props': props
        })
        
        # Check if entry point is in this section
        if entry_point >= sect.VirtualAddress and entry_point < (sect.VirtualAddress + sect.Misc_VirtualSize):
            entry_section_name = name
            
    section = {
        'sections': sections_list,
        'entry': entry_section_name
    }
    
    # Imports Info
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            lib_name = entry.dll.decode('utf-8', errors='ignore')
            func_names = []
            for imp in entry.imports:
                if imp.name:
                    func_names.append(imp.name.decode('utf-8', errors='ignore'))
                else:
                    func_names.append(f"ord{imp.ordinal}")
            imports[lib_name] = func_names
            
    # Exports Info
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name:
                exports.append(sym.name.decode('utf-8', errors='ignore'))
                
    # Data Directories
    datadirectories = []
    if pe.OPTIONAL_HEADER:
        for i in range(16): # EMBER takes up to 15 directories
            if i < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
                datadirectories.append({
                    'size': dir_entry.Size,
                    'virtual_address': dir_entry.VirtualAddress
                })
            else:
                datadirectories.append({'size': 0, 'virtual_address': 0})
                
    pe.close()
    
    # Assemble raw obj matching EMBER's JSON fields
    raw_obj = {
        'histogram': histogram,
        'byteentropy': byteentropy,
        'strings': strings,
        'general': general,
        'header': header,
        'section': section,
        'imports': imports,
        'exports': exports,
        'datadirectories': datadirectories
    }
    
    return raw_obj

def get_pe_features_vector(file_path):
    raw_obj = extract_raw_pe_features(file_path)
    extractor = PEFeatureExtractor()
    feature_vector = extractor.process_raw_features(raw_obj)
    return feature_vector, raw_obj

if __name__ == '__main__':
    # Simple test run on python.exe or server.py itself
    import sys
    test_file = sys.executable  # Path to python.exe
    print(f"Testing extractor_helper on: {test_file}")
    vec, raw = get_pe_features_vector(test_file)
    print(f"Extracted feature vector shape: {vec.shape}")
    print(f"File size: {raw['general']['size']} bytes")
    print(f"Sections count: {len(raw['section']['sections'])}")
    print(f"Imports libraries: {list(raw['imports'].keys())[:5]}")
