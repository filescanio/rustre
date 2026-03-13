use goblin::pe::section_table::{SectionTable, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ};
use goblin::pe::PE;
use log::{debug, error};
use serde::Serialize;

const IMAGE_FILE_MACHINE_I386: u16 = 0x14c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedString {
    pub string: String,
    pub offset: usize,
}

struct SectionInfo {
    pointer_to_raw_data: usize,
    size_of_raw_data: usize,
    virtual_address: usize,
    characteristics: u32,
    name: String,
}

fn parse_sections(pe: &PE, data: &[u8]) -> Vec<SectionInfo> {
    pe.sections
        .iter()
        .filter_map(|s| {
            let raw_off = s.pointer_to_raw_data as usize;
            let raw_sz = s.size_of_raw_data as usize;
            if raw_off + raw_sz > data.len() {
                None
            } else {
                Some(SectionInfo {
                    pointer_to_raw_data: raw_off,
                    size_of_raw_data: raw_sz,
                    virtual_address: s.virtual_address as usize,
                    characteristics: s.characteristics,
                    name: section_name(s),
                })
            }
        })
        .collect()
}

fn section_name(s: &SectionTable) -> String {
    let name_bytes = &s.name;
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
    String::from_utf8_lossy(&name_bytes[..end]).to_string()
}

fn section_data<'a>(s: &SectionInfo, data: &'a [u8]) -> &'a [u8] {
    &data[s.pointer_to_raw_data..s.pointer_to_raw_data + s.size_of_raw_data]
}

fn find_rdata_section(sections: &[SectionInfo]) -> Option<usize> {
    sections.iter().position(|s| s.name == ".rdata")
}

// --- Reading a string at a known offset ---

fn is_printable_ascii(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// Read printable ASCII from `data[offset..]` until null or non-printable.
fn read_string_at(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let mut end = offset;
    while end < data.len() && data[end] != 0 && is_printable_ascii(data[end]) {
        end += 1;
    }
    if end == offset {
        return None;
    }
    Some(String::from_utf8_lossy(&data[offset..end]).into_owned())
}

/// Read exactly `len` bytes from `data[offset..]` and validate as printable ASCII.
fn read_exact_string_at(data: &[u8], offset: usize, len: usize) -> Option<String> {
    if offset + len > data.len() {
        return None;
    }
    let slice = &data[offset..offset + len];
    if slice.iter().all(|&b| is_printable_ascii(b)) {
        Some(String::from_utf8_lossy(slice).into_owned())
    } else {
        None
    }
}

// --- Xref scanning (byte pattern matching) ---

fn read_i32_le(buf: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

const AMD64_LEA_PREFIXES: &[[u8; 3]] = &[
    [0x48, 0x8D, 0x05], // lea rax,[rip+X]
    [0x48, 0x8D, 0x0D], // lea rcx,[rip+X]
    [0x48, 0x8D, 0x15], // lea rdx,[rip+X]
    [0x48, 0x8D, 0x1D], // lea rbx,[rip+X]
    [0x48, 0x8D, 0x2D], // lea rbp,[rip+X]
    [0x48, 0x8D, 0x35], // lea rsi,[rip+X]
    [0x48, 0x8D, 0x3D], // lea rdi,[rip+X]
    [0x4C, 0x8D, 0x05], // lea r8,[rip+X]
    [0x4C, 0x8D, 0x0D], // lea r9,[rip+X]
    [0x4C, 0x8D, 0x15], // lea r10,[rip+X]
    [0x4C, 0x8D, 0x1D], // lea r11,[rip+X]
    [0x4C, 0x8D, 0x25], // lea r12,[rip+X]
    [0x4C, 0x8D, 0x2D], // lea r13,[rip+X]
    [0x4C, 0x8D, 0x35], // lea r14,[rip+X]
    [0x4C, 0x8D, 0x3D], // lea r15,[rip+X]
];

fn find_amd64_lea_xrefs(code: &[u8], base_addr: u64) -> Vec<u64> {
    const INSN_LEN: u64 = 7;
    let mut results = Vec::new();
    if code.len() < 7 {
        return results;
    }
    for i in 0..code.len() - 6 {
        for prefix in AMD64_LEA_PREFIXES {
            if code[i] == prefix[0] && code[i + 1] == prefix[1] && code[i + 2] == prefix[2] {
                let offset = read_i32_le(code, i + 3);
                let target = (base_addr as i64)
                    .wrapping_add(i as i64)
                    .wrapping_add(offset as i64)
                    .wrapping_add(INSN_LEN as i64);
                results.push(target as u64);
                break;
            }
        }
    }
    results
}

const I386_LEA_PREFIXES: &[[u8; 2]] = &[
    [0x8D, 0x05], // lea eax,ds:X
    [0x8D, 0x0D], // lea ecx,ds:X
    [0x8D, 0x15], // lea edx,ds:X
    [0x8D, 0x1D], // lea ebx,ds:X
    [0x8D, 0x35], // lea esi,ds:X
    [0x8D, 0x3D], // lea edi,ds:X
];

fn find_i386_lea_xrefs(code: &[u8]) -> Vec<u64> {
    let mut results = Vec::new();
    if code.len() < 6 {
        return results;
    }
    for i in 0..code.len() - 5 {
        for prefix in I386_LEA_PREFIXES {
            if code[i] == prefix[0] && code[i + 1] == prefix[1] {
                results.push(read_u32_le(code, i + 2) as u64);
                break;
            }
        }
    }
    results
}

fn find_i386_push_xrefs(code: &[u8]) -> Vec<u64> {
    let mut results = Vec::new();
    if code.len() < 5 {
        return results;
    }
    for i in 0..code.len() - 4 {
        if code[i] == 0x68 {
            results.push(read_u32_le(code, i + 1) as u64);
        }
    }
    results
}

const I386_MOV_OPCODES: &[u8] = &[0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF];

fn find_i386_mov_xrefs(code: &[u8]) -> Vec<u64> {
    let mut results = Vec::new();
    if code.len() < 5 {
        return results;
    }
    for i in 0..code.len() - 4 {
        if I386_MOV_OPCODES.contains(&code[i]) {
            results.push(read_u32_le(code, i + 1) as u64);
        }
    }
    results
}

fn collect_xrefs_from_sections(
    sections: &[SectionInfo],
    data: &[u8],
    image_base: u64,
    machine: u16,
    image_low: u64,
    image_high: u64,
) -> Vec<u64> {
    let mut all_xrefs = Vec::new();

    for s in sections {
        if s.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let code = section_data(s, data);
        let section_base = image_base + s.virtual_address as u64;

        let mut xrefs = match machine {
            IMAGE_FILE_MACHINE_AMD64 => find_amd64_lea_xrefs(code, section_base),
            IMAGE_FILE_MACHINE_I386 => {
                let mut x = find_i386_lea_xrefs(code);
                x.extend(find_i386_push_xrefs(code));
                x.extend(find_i386_mov_xrefs(code));
                x
            }
            _ => Vec::new(),
        };

        xrefs.retain(|&addr| addr >= image_low && addr < image_high);
        all_xrefs.extend(xrefs);
    }

    all_xrefs
}

// --- Struct string candidates ---

struct StructStringCandidate {
    address: u64,
    length: u64,
}

fn get_struct_string_candidates_with_pointer_size(
    buf: &[u8],
    psize: usize,
    max_length: u64,
    image_low: u64,
    image_high: u64,
) -> Vec<StructStringCandidate> {
    let word_size = psize / 8;
    let mut results = Vec::new();

    if buf.len() < word_size * 2 {
        return results;
    }

    let read_word = match psize {
        32 => |b: &[u8], off: usize| read_u32_le(b, off) as u64,
        64 => read_u64_le,
        _ => return results,
    };

    let num_words = buf.len() / word_size;
    if num_words < 2 {
        return results;
    }

    let mut last = read_word(buf, 0);
    for i in 1..num_words {
        let current = read_word(buf, i * word_size);
        let address = last;
        let length = current;
        last = current;

        if address == 0 || length == 0 {
            continue;
        }
        if length > max_length {
            continue;
        }
        if address < image_low || address >= image_high {
            continue;
        }

        results.push(StructStringCandidate { address, length });
    }

    results
}

fn collect_struct_strings(
    sections: &[SectionInfo],
    data: &[u8],
    pe: &PE,
    image_base: u64,
    image_low: u64,
    image_high: u64,
    max_section_size: u64,
) -> Vec<ExtractedString> {
    let machine = pe.header.coff_header.machine;
    let psize: usize = match machine {
        IMAGE_FILE_MACHINE_AMD64 => 64,
        IMAGE_FILE_MACHINE_I386 => 32,
        _ => return Vec::new(),
    };

    let mut results = Vec::new();

    for s in sections {
        if s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            continue;
        }
        if s.characteristics & IMAGE_SCN_MEM_READ == 0 {
            continue;
        }
        if s.name != ".rdata" && s.name != ".data" {
            continue;
        }

        let buf = section_data(s, data);
        let candidates =
            get_struct_string_candidates_with_pointer_size(buf, psize, max_section_size, image_low, image_high);

        for c in candidates {
            let va = c.address;
            if va < image_low || va >= image_high {
                continue;
            }
            let rva = va - image_base;

            let target_section = sections.iter().find(|sec| {
                let sec_va = sec.virtual_address as u64;
                rva >= sec_va && rva < sec_va + sec.size_of_raw_data as u64
            });
            let target_section = match target_section {
                Some(s) => s,
                None => continue,
            };
            if target_section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                continue;
            }
            if target_section.characteristics & IMAGE_SCN_MEM_READ == 0 {
                continue;
            }

            let raw_offset = (rva as usize)
                .wrapping_sub(target_section.virtual_address)
                .wrapping_add(target_section.pointer_to_raw_data);

            let len = c.length as usize;
            if let Some(s) = read_exact_string_at(data, raw_offset, len) {
                results.push(ExtractedString {
                    string: s,
                    offset: raw_offset,
                });
            }
        }
    }

    results
}

// --- Main entry point ---

pub fn extract_rust_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let pe = match PE::parse(data) {
        Ok(pe) => pe,
        Err(e) => {
            error!("failed to parse PE: {}", e);
            return Vec::new();
        }
    };

    let image_base = pe.image_base as u64;
    let image_size = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.size_of_image as u64)
        .unwrap_or(0);
    let image_low = image_base;
    let image_high = image_base + image_size;
    let machine = pe.header.coff_header.machine;

    if machine != IMAGE_FILE_MACHINE_I386 && machine != IMAGE_FILE_MACHINE_AMD64 {
        error!("unsupported PE architecture: 0x{:04x}", machine);
        return Vec::new();
    }

    let sections = parse_sections(&pe, data);

    let rdata_idx = match find_rdata_section(&sections) {
        Some(i) => i,
        None => {
            error!("no .rdata section found");
            return Vec::new();
        }
    };

    let rdata = &sections[rdata_idx];
    let start_rdata = rdata.pointer_to_raw_data;
    let end_rdata = start_rdata + rdata.size_of_raw_data;
    let rdata_va = rdata.virtual_address;

    debug!(
        ".rdata: raw {:#x}..{:#x}, VA {:#x}, size {}",
        start_rdata, end_rdata, rdata_va, rdata.size_of_raw_data
    );

    let max_section_size = sections.iter().map(|s| s.size_of_raw_data as u64).max().unwrap_or(0);

    // 1. Struct string candidates: read exact (pointer, length) strings
    let struct_strings = collect_struct_strings(
        &sections, data, &pe, image_base, image_low, image_high, max_section_size,
    );
    debug!("struct candidate strings: {}", struct_strings.len());

    // 2. Code xrefs: read string at each target address
    let code_xrefs = collect_xrefs_from_sections(&sections, data, image_base, machine, image_low, image_high);
    debug!("code xrefs found: {}", code_xrefs.len());

    let mut code_strings: Vec<ExtractedString> = Vec::new();
    for &addr in &code_xrefs {
        let raw = addr
            .wrapping_sub(image_base)
            .wrapping_sub(rdata_va as u64)
            .wrapping_add(start_rdata as u64) as usize;
        if raw < start_rdata || raw >= end_rdata {
            continue;
        }
        if let Some(s) = read_string_at(data, raw) {
            code_strings.push(ExtractedString {
                string: s,
                offset: raw,
            });
        }
    }
    debug!("code xref strings: {}", code_strings.len());

    // 3. Merge, deduplicate by offset, filter by min_length
    let mut all_strings = struct_strings;
    all_strings.extend(code_strings);
    all_strings.sort_by_key(|s| s.offset);
    all_strings.dedup_by_key(|s| s.offset);
    all_strings.retain(|s| s.string.len() >= min_length);

    debug!("final extracted strings: {}", all_strings.len());

    all_strings
}

pub fn is_pe(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == b'M' && data[1] == b'Z'
}
