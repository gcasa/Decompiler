#import "DecompilerEngine.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#define bpf_insn capstone_bpf_insn
#import <capstone/capstone.h>
#undef bpf_insn
#pragma clang diagnostic pop

typedef struct {
    cs_arch arch;
    cs_mode mode;
    uint64_t address;
    NSUInteger offset;
    NSUInteger size;
    NSString *formatName;
    NSString *architectureName;
    NSString *entryPointDescription;
    NSArray<NSString *> *warnings;
} DCImageSlice;

@implementation DCDecompilerResult
@end

@interface DCInstruction : NSObject
@property (nonatomic) uint64_t address;
@property (nonatomic, copy) NSString *mnemonic;
@property (nonatomic, copy) NSString *operands;
@property (nonatomic, copy) NSString *bytes;
@end

@implementation DCInstruction
@end

@implementation DCDecompilerEngine

+ (NSArray<NSString *> *)pseudocodeStyleNames {
    return @[@"Structured C", @"Compact C", @"Verbose IR", @"Control Flow"];
}

- (DCDecompilerResult *)decompileFileAtURL:(NSURL *)url
                                     style:(DCPseudocodeStyle)style
                                     error:(NSError **)error {
    NSData *data = [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:error];
    if (!data) {
        return nil;
    }

    DCImageSlice slice = [self bestSliceForData:data fileName:url.lastPathComponent];
    if (slice.size == 0 || slice.offset >= data.length) {
        if (error) {
            *error = [NSError errorWithDomain:@"Decompiler"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"No executable bytes were found in this file."}];
        }
        return nil;
    }

    NSUInteger maxSize = MIN(slice.size, data.length - slice.offset);
    const uint8_t *code = (const uint8_t *)data.bytes + slice.offset;
    NSArray<DCInstruction *> *instructions = [self disassembleBytes:code
                                                              length:maxSize
                                                             address:slice.address
                                                                arch:slice.arch
                                                                mode:slice.mode
                                                               error:error];
    if (!instructions) {
        return nil;
    }

    DCDecompilerResult *result = [DCDecompilerResult new];
    result.formatName = slice.formatName;
    result.architectureName = slice.architectureName;
    result.entryPointDescription = slice.entryPointDescription;
    result.disassembly = [self renderDisassembly:instructions];
    result.pseudocode = [self renderPseudocode:instructions style:style name:url.lastPathComponent];
    result.warnings = slice.warnings ?: @[];
    return result;
}

#pragma mark - Container Parsing

static uint16_t dc_read16(const uint8_t *p, BOOL swap) {
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return swap ? CFSwapInt16(v) : v;
}

static uint32_t dc_read32(const uint8_t *p, BOOL swap) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return swap ? CFSwapInt32(v) : v;
}

static uint64_t dc_read64(const uint8_t *p, BOOL swap) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return swap ? CFSwapInt64(v) : v;
}

- (DCImageSlice)bestSliceForData:(NSData *)data fileName:(NSString *)fileName {
    const uint8_t *bytes = data.bytes;
    NSUInteger length = data.length;
    DCImageSlice empty = {0};
    empty.warnings = @[];

    if (length >= 4) {
        uint32_t magicBE = CFSwapInt32BigToHost(*(const uint32_t *)bytes);
        if (magicBE == 0xcafebabe || magicBE == 0xcafebabf) {
            DCImageSlice fat = [self parseFatMachO:data];
            if (fat.size > 0) {
                return fat;
            }
        }

        uint32_t magicLE = CFSwapInt32LittleToHost(*(const uint32_t *)bytes);
        if (magicLE == 0xfeedface || magicLE == 0xfeedfacf || magicLE == 0xcefaedfe || magicLE == 0xcffaedfe) {
            DCImageSlice macho = [self parseMachO:data offset:0 inheritedName:nil];
            if (macho.size > 0) {
                return macho;
            }
        }
    }

    if (length >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') {
        DCImageSlice elf = [self parseELF:data];
        if (elf.size > 0) {
            return elf;
        }
    }

    if (length >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
        DCImageSlice pe = [self parsePE:data];
        if (pe.size > 0) {
            return pe;
        }
    }

    DCImageSlice raw = [self rawSliceForData:data fileName:fileName];
    raw.warnings = @[@"Unrecognized executable container. Disassembling from byte 0 as a raw binary."];
    return raw;
}

- (DCImageSlice)parseFatMachO:(NSData *)data {
    const uint8_t *b = data.bytes;
    NSUInteger len = data.length;
    DCImageSlice empty = {0};
    if (len < 8) return empty;

    uint32_t nfat = CFSwapInt32BigToHost(*(const uint32_t *)(b + 4));
    NSUInteger archSize = 20;
    if (8 + (NSUInteger)nfat * archSize > len) return empty;

    NSArray<NSNumber *> *preferred = @[@(0x0100000c), @(0x01000007), @(12), @(7), @(18)];
    for (NSNumber *cpuNumber in preferred) {
        uint32_t desired = cpuNumber.unsignedIntValue;
        for (uint32_t i = 0; i < nfat; i++) {
            const uint8_t *a = b + 8 + i * archSize;
            uint32_t cputype = CFSwapInt32BigToHost(*(const uint32_t *)a);
            uint32_t offset = CFSwapInt32BigToHost(*(const uint32_t *)(a + 8));
            if (cputype == desired && offset < len) {
                DCImageSlice s = [self parseMachO:data offset:offset inheritedName:@"Universal Mach-O"];
                if (s.size > 0) {
                    return s;
                }
            }
        }
    }

    uint32_t offset = CFSwapInt32BigToHost(*(const uint32_t *)(b + 16));
    if (offset < len) {
        return [self parseMachO:data offset:offset inheritedName:@"Universal Mach-O"];
    }
    return empty;
}

- (DCImageSlice)parseMachO:(NSData *)data offset:(NSUInteger)base inheritedName:(NSString *)inheritedName {
    const uint8_t *b = data.bytes;
    NSUInteger len = data.length;
    DCImageSlice s = {0};
    if (base + 32 > len) return s;

    uint32_t magicRaw;
    memcpy(&magicRaw, b + base, sizeof(magicRaw));
    BOOL swap = (magicRaw == 0xcefaedfe || magicRaw == 0xcffaedfe);
    uint32_t magic = dc_read32(b + base, swap);
    BOOL is64 = (magic == 0xfeedfacf);
    if (!(magic == 0xfeedface || magic == 0xfeedfacf)) return s;

    uint32_t cputype = dc_read32(b + base + 4, swap);
    uint32_t ncmds = dc_read32(b + base + 16, swap);
    uint64_t textVM = 0;
    uint64_t entry = 0;
    NSUInteger textOffset = 0;
    NSUInteger textSize = 0;
    NSUInteger cursor = base + (is64 ? 32 : 28);

    for (uint32_t i = 0; i < ncmds && cursor + 8 <= len; i++) {
        uint32_t cmd = dc_read32(b + cursor, swap);
        uint32_t cmdsize = dc_read32(b + cursor + 4, swap);
        if (cmdsize < 8 || cursor + cmdsize > len) break;

        if ((cmd == 0x19 || cmd == 0x1) && cmdsize >= (is64 ? 72 : 56)) {
            uint32_t nsects = dc_read32(b + cursor + (is64 ? 64 : 48), swap);
            NSUInteger sectionCursor = cursor + (is64 ? 72 : 56);
            NSUInteger sectionSize = is64 ? 80 : 68;
            for (uint32_t j = 0; j < nsects && sectionCursor + sectionSize <= cursor + cmdsize; j++) {
                const char *sectname = (const char *)(b + sectionCursor);
                const char *segname = (const char *)(b + sectionCursor + 16);
                if (strncmp(sectname, "__text", 6) == 0 && strncmp(segname, "__TEXT", 6) == 0) {
                    textVM = is64 ? dc_read64(b + sectionCursor + 32, swap) : dc_read32(b + sectionCursor + 32, swap);
                    textSize = (NSUInteger)(is64 ? dc_read64(b + sectionCursor + 40, swap) : dc_read32(b + sectionCursor + 36, swap));
                    textOffset = (NSUInteger)dc_read32(b + sectionCursor + (is64 ? 48 : 40), swap);
                }
                sectionCursor += sectionSize;
            }
        } else if (cmd == 0x80000028 && cmdsize >= 24) {
            entry = dc_read64(b + cursor + 8, swap);
        }
        cursor += cmdsize;
    }

    if (textOffset == 0 || textSize == 0) return s;
    s.offset = base + textOffset;
    s.size = MIN(textSize, len - s.offset);
    s.address = entry ? textVM + entry : textVM;
    s.formatName = inheritedName ?: (is64 ? @"Mach-O 64-bit" : @"Mach-O 32-bit");
    s.entryPointDescription = entry ? [NSString stringWithFormat:@"entryoff 0x%llx", entry] : @"__TEXT,__text";
    [self configureSlice:&s forMachCPU:cputype is64:is64];
    return s;
}

- (void)configureSlice:(DCImageSlice *)s forMachCPU:(uint32_t)cputype is64:(BOOL)is64 {
    switch (cputype) {
        case 0x01000007:
        case 7:
            s->arch = CS_ARCH_X86;
            s->mode = is64 ? CS_MODE_64 : CS_MODE_32;
            s->architectureName = is64 ? @"x86_64" : @"x86";
            break;
        case 0x0100000c:
        case 12:
            s->arch = CS_ARCH_ARM64;
            s->mode = CS_MODE_ARM;
            s->architectureName = is64 ? @"arm64" : @"arm";
            break;
        case 18:
            s->arch = CS_ARCH_PPC;
            s->mode = is64 ? CS_MODE_64 : CS_MODE_32;
            s->architectureName = is64 ? @"ppc64" : @"ppc";
            break;
        default:
            s->arch = CS_ARCH_X86;
            s->mode = CS_MODE_64;
            s->architectureName = @"unknown Mach CPU; assumed x86_64";
            s->warnings = @[@"Unsupported Mach-O CPU type for automatic selection. Tried x86_64 as a fallback."];
            break;
    }
}

- (DCImageSlice)parseELF:(NSData *)data {
    const uint8_t *b = data.bytes;
    NSUInteger len = data.length;
    DCImageSlice s = {0};
    if (len < 64) return s;

    BOOL is64 = b[4] == 2;
    BOOL big = b[5] == 2;
    BOOL swap = big != (CFByteOrderGetCurrent() == CFByteOrderBigEndian);
    uint16_t machine = dc_read16(b + 18, swap);
    uint64_t entry = is64 ? dc_read64(b + 24, swap) : dc_read32(b + 24, swap);
    uint64_t phoff = is64 ? dc_read64(b + 32, swap) : dc_read32(b + 28, swap);
    uint16_t phentsize = dc_read16(b + (is64 ? 54 : 42), swap);
    uint16_t phnum = dc_read16(b + (is64 ? 56 : 44), swap);

    uint64_t chosenVA = 0;
    NSUInteger chosenOffset = 0;
    NSUInteger chosenSize = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        NSUInteger p = (NSUInteger)phoff + (NSUInteger)i * phentsize;
        if (p + phentsize > len || phentsize < (is64 ? 56 : 32)) break;
        uint32_t type = dc_read32(b + p, swap);
        uint32_t flags = is64 ? dc_read32(b + p + 4, swap) : dc_read32(b + p + 24, swap);
        uint64_t off = is64 ? dc_read64(b + p + 8, swap) : dc_read32(b + p + 4, swap);
        uint64_t va = is64 ? dc_read64(b + p + 16, swap) : dc_read32(b + p + 8, swap);
        uint64_t filesz = is64 ? dc_read64(b + p + 32, swap) : dc_read32(b + p + 16, swap);
        if (type == 1 && (flags & 0x1) && off < len && filesz > 0) {
            if (entry >= va && entry < va + filesz) {
                chosenOffset = (NSUInteger)(off + (entry - va));
                chosenSize = (NSUInteger)(filesz - (entry - va));
                chosenVA = entry;
                break;
            }
            if (chosenSize == 0) {
                chosenOffset = (NSUInteger)off;
                chosenSize = (NSUInteger)filesz;
                chosenVA = va;
            }
        }
    }

    if (chosenSize == 0) return s;
    s.offset = chosenOffset;
    s.size = MIN(chosenSize, len - s.offset);
    s.address = chosenVA;
    s.formatName = is64 ? @"ELF 64-bit" : @"ELF 32-bit";
    s.entryPointDescription = [NSString stringWithFormat:@"0x%llx", entry];
    [self configureSlice:&s forELFMachine:machine is64:is64 bigEndian:big];
    return s;
}

- (void)configureSlice:(DCImageSlice *)s forELFMachine:(uint16_t)machine is64:(BOOL)is64 bigEndian:(BOOL)big {
    switch (machine) {
        case 3:
        case 62:
            s->arch = CS_ARCH_X86;
            s->mode = is64 ? CS_MODE_64 : CS_MODE_32;
            s->architectureName = is64 ? @"x86_64" : @"x86";
            break;
        case 40:
            s->arch = CS_ARCH_ARM;
            s->mode = CS_MODE_ARM;
            s->architectureName = @"arm";
            break;
        case 183:
            s->arch = CS_ARCH_ARM64;
            s->mode = CS_MODE_ARM;
            s->architectureName = @"arm64";
            break;
        case 8:
            s->arch = CS_ARCH_MIPS;
            s->mode = (is64 ? CS_MODE_64 : CS_MODE_32) | (big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);
            s->architectureName = is64 ? @"mips64" : @"mips";
            break;
        case 20:
        case 21:
            s->arch = CS_ARCH_PPC;
            s->mode = (is64 ? CS_MODE_64 : CS_MODE_32) | CS_MODE_BIG_ENDIAN;
            s->architectureName = is64 ? @"ppc64" : @"ppc";
            break;
        case 243:
            s->arch = CS_ARCH_RISCV;
            s->mode = is64 ? CS_MODE_RISCV64 : CS_MODE_RISCV32;
            s->architectureName = is64 ? @"riscv64" : @"riscv32";
            break;
        default:
            s->arch = CS_ARCH_X86;
            s->mode = is64 ? CS_MODE_64 : CS_MODE_32;
            s->architectureName = @"unknown ELF machine; assumed x86";
            s->warnings = @[@"Unsupported ELF machine for automatic selection. Tried x86 as a fallback."];
            break;
    }
}

- (DCImageSlice)parsePE:(NSData *)data {
    const uint8_t *b = data.bytes;
    NSUInteger len = data.length;
    DCImageSlice s = {0};
    if (len < 0x40) return s;
    uint32_t peOff = CFSwapInt32LittleToHost(*(const uint32_t *)(b + 0x3c));
    if (peOff + 24 > len || memcmp(b + peOff, "PE\0\0", 4) != 0) return s;

    uint16_t machine = CFSwapInt16LittleToHost(*(const uint16_t *)(b + peOff + 4));
    uint16_t sectionCount = CFSwapInt16LittleToHost(*(const uint16_t *)(b + peOff + 6));
    uint16_t optSize = CFSwapInt16LittleToHost(*(const uint16_t *)(b + peOff + 20));
    NSUInteger opt = peOff + 24;
    if (opt + optSize > len || optSize < 32) return s;
    uint16_t optMagic = CFSwapInt16LittleToHost(*(const uint16_t *)(b + opt));
    BOOL is64 = optMagic == 0x20b;
    uint32_t entryRVA = CFSwapInt32LittleToHost(*(const uint32_t *)(b + opt + 16));
    uint64_t imageBase = is64 ? CFSwapInt64LittleToHost(*(const uint64_t *)(b + opt + 24)) : CFSwapInt32LittleToHost(*(const uint32_t *)(b + opt + 28));

    NSUInteger sectionTable = opt + optSize;
    NSUInteger chosenOffset = 0;
    NSUInteger chosenSize = 0;
    for (uint16_t i = 0; i < sectionCount; i++) {
        NSUInteger sec = sectionTable + (NSUInteger)i * 40;
        if (sec + 40 > len) break;
        uint32_t virtualSize = CFSwapInt32LittleToHost(*(const uint32_t *)(b + sec + 8));
        uint32_t virtualAddress = CFSwapInt32LittleToHost(*(const uint32_t *)(b + sec + 12));
        uint32_t rawSize = CFSwapInt32LittleToHost(*(const uint32_t *)(b + sec + 16));
        uint32_t rawPtr = CFSwapInt32LittleToHost(*(const uint32_t *)(b + sec + 20));
        uint32_t chars = CFSwapInt32LittleToHost(*(const uint32_t *)(b + sec + 36));
        uint32_t span = MAX(virtualSize, rawSize);
        if ((chars & 0x20000000) && entryRVA >= virtualAddress && entryRVA < virtualAddress + span) {
            chosenOffset = rawPtr + (entryRVA - virtualAddress);
            chosenSize = rawSize - (entryRVA - virtualAddress);
            break;
        }
        if ((chars & 0x20000000) && chosenSize == 0) {
            chosenOffset = rawPtr;
            chosenSize = rawSize;
        }
    }

    if (chosenSize == 0 || chosenOffset >= len) return s;
    s.offset = chosenOffset;
    s.size = MIN(chosenSize, len - s.offset);
    s.address = imageBase + entryRVA;
    s.formatName = is64 ? @"PE/COFF 64-bit" : @"PE/COFF 32-bit";
    s.entryPointDescription = [NSString stringWithFormat:@"RVA 0x%x", entryRVA];
    switch (machine) {
        case 0x14c:
            s.arch = CS_ARCH_X86;
            s.mode = CS_MODE_32;
            s.architectureName = @"x86";
            break;
        case 0x8664:
            s.arch = CS_ARCH_X86;
            s.mode = CS_MODE_64;
            s.architectureName = @"x86_64";
            break;
        case 0x1c0:
        case 0x1c4:
            s.arch = CS_ARCH_ARM;
            s.mode = CS_MODE_ARM;
            s.architectureName = @"arm";
            break;
        case 0xaa64:
            s.arch = CS_ARCH_ARM64;
            s.mode = CS_MODE_ARM;
            s.architectureName = @"arm64";
            break;
        default:
            s.arch = CS_ARCH_X86;
            s.mode = is64 ? CS_MODE_64 : CS_MODE_32;
            s.architectureName = @"unknown PE machine; assumed x86";
            s.warnings = @[@"Unsupported PE machine for automatic selection. Tried x86 as a fallback."];
            break;
    }
    return s;
}

- (DCImageSlice)rawSliceForData:(NSData *)data fileName:(NSString *)fileName {
    DCImageSlice s = {0};
    s.offset = 0;
    s.size = data.length;
    s.address = 0;
    s.formatName = @"Raw binary";
    s.entryPointDescription = @"offset 0";
    s.arch = CS_ARCH_X86;
    s.mode = CS_MODE_64;
    s.architectureName = @"x86_64";
    NSString *lower = fileName.lowercaseString;
    if ([lower containsString:@"arm64"] || [lower containsString:@"aarch64"]) {
        s.arch = CS_ARCH_ARM64;
        s.mode = CS_MODE_ARM;
        s.architectureName = @"arm64";
    } else if ([lower containsString:@"arm"]) {
        s.arch = CS_ARCH_ARM;
        s.mode = CS_MODE_ARM;
        s.architectureName = @"arm";
    } else if ([lower containsString:@"x86"] && ![lower containsString:@"64"]) {
        s.mode = CS_MODE_32;
        s.architectureName = @"x86";
    }
    return s;
}

#pragma mark - Capstone

- (NSArray<DCInstruction *> *)disassembleBytes:(const uint8_t *)code
                                        length:(NSUInteger)length
                                       address:(uint64_t)address
                                          arch:(cs_arch)arch
                                          mode:(cs_mode)mode
                                         error:(NSError **)error {
    csh handle;
    cs_err err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        if (error) {
            *error = [NSError errorWithDomain:@"Decompiler"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Capstone could not open this architecture/mode: %s", cs_strerror(err)]}];
        }
        return nil;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn *insn = NULL;
    size_t count = cs_disasm(handle, code, length, address, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        if (error) {
            *error = [NSError errorWithDomain:@"Decompiler"
                                         code:3
                                     userInfo:@{NSLocalizedDescriptionKey: @"Capstone did not decode any instructions from the selected executable bytes."}];
        }
        return nil;
    }

    NSMutableArray<DCInstruction *> *result = [NSMutableArray arrayWithCapacity:count];
    for (size_t i = 0; i < count; i++) {
        DCInstruction *di = [DCInstruction new];
        di.address = insn[i].address;
        di.mnemonic = [NSString stringWithUTF8String:insn[i].mnemonic];
        di.operands = [NSString stringWithUTF8String:insn[i].op_str];
        NSMutableString *byteString = [NSMutableString string];
        for (uint16_t j = 0; j < insn[i].size; j++) {
            [byteString appendFormat:@"%02x", insn[i].bytes[j]];
            if (j + 1 < insn[i].size) [byteString appendString:@" "];
        }
        di.bytes = byteString;
        [result addObject:di];
    }

    cs_free(insn, count);
    cs_close(&handle);
    return result;
}

#pragma mark - Rendering

- (NSString *)renderDisassembly:(NSArray<DCInstruction *> *)instructions {
    NSMutableString *out = [NSMutableString string];
    for (DCInstruction *i in instructions) {
        [out appendFormat:@"0x%llx  %-24@  %@ %@\n", i.address, i.bytes, i.mnemonic, i.operands];
    }
    return out;
}

- (NSString *)renderPseudocode:(NSArray<DCInstruction *> *)instructions
                          style:(DCPseudocodeStyle)style
                           name:(NSString *)name {
    switch (style) {
        case DCPseudocodeStyleCompactC:
            return [self renderCompactC:instructions name:name];
        case DCPseudocodeStyleVerboseIR:
            return [self renderVerboseIR:instructions name:name];
        case DCPseudocodeStyleControlFlow:
            return [self renderControlFlow:instructions name:name];
        case DCPseudocodeStyleStructuredC:
        default:
            return [self renderStructuredC:instructions name:name];
    }
}

- (NSString *)renderStructuredC:(NSArray<DCInstruction *> *)instructions name:(NSString *)name {
    NSMutableString *out = [NSMutableString stringWithFormat:@"// Decompiled pseudocode for %@\nint function_entry(void) {\n", name];
    for (DCInstruction *i in instructions) {
        NSString *line = [self cLineForInstruction:i compact:NO];
        [out appendFormat:@"    %@\n", line];
        if ([self isReturnInstruction:i]) {
            [out appendString:@"}\n"];
            return out;
        }
    }
    [out appendString:@"    return 0;\n}\n"];
    return out;
}

- (NSString *)renderCompactC:(NSArray<DCInstruction *> *)instructions name:(NSString *)name {
    NSMutableString *out = [NSMutableString stringWithFormat:@"int function_entry(void) { // %@\n", name];
    for (DCInstruction *i in instructions) {
        [out appendFormat:@"    %@\n", [self cLineForInstruction:i compact:YES]];
    }
    [out appendString:@"}\n"];
    return out;
}

- (NSString *)renderVerboseIR:(NSArray<DCInstruction *> *)instructions name:(NSString *)name {
    NSMutableString *out = [NSMutableString stringWithFormat:@"; Linear IR for %@\n", name];
    NSUInteger index = 0;
    for (DCInstruction *i in instructions) {
        [out appendFormat:@"i%04lu: addr=0x%llx op=%@ args=[%@] bytes=[%@]\n",
         (unsigned long)index++, i.address, i.mnemonic, i.operands, i.bytes];
    }
    return out;
}

- (NSString *)renderControlFlow:(NSArray<DCInstruction *> *)instructions name:(NSString *)name {
    NSMutableString *out = [NSMutableString stringWithFormat:@"// Control-flow oriented pseudocode for %@\nvoid function_entry(void) {\n", name];
    for (DCInstruction *i in instructions) {
        NSString *mn = i.mnemonic.lowercaseString;
        if ([self isConditionalJump:mn]) {
            [out appendFormat:@"block_%llx:\n    if (%@) goto %@;\n", i.address, [self conditionForJump:mn], [self sanitizedTarget:i.operands]];
        } else if ([mn isEqualToString:@"jmp"] || [mn isEqualToString:@"b"]) {
            [out appendFormat:@"block_%llx:\n    goto %@;\n", i.address, [self sanitizedTarget:i.operands]];
        } else {
            [out appendFormat:@"    %@\n", [self cLineForInstruction:i compact:NO]];
        }
    }
    [out appendString:@"}\n"];
    return out;
}

- (NSString *)cLineForInstruction:(DCInstruction *)i compact:(BOOL)compact {
    NSString *mn = i.mnemonic.lowercaseString;
    NSArray<NSString *> *ops = [self operandsFromString:i.operands];
    NSString *comment = compact ? @"" : [NSString stringWithFormat:@" // 0x%llx: %@ %@", i.address, i.mnemonic, i.operands];

    if (([mn isEqualToString:@"mov"] || [mn isEqualToString:@"movz"] || [mn isEqualToString:@"ldr"] || [mn isEqualToString:@"lea"]) && ops.count >= 2) {
        return [NSString stringWithFormat:@"%@ = %@;%@", ops[0], ops[1], comment];
    }
    if (([mn isEqualToString:@"str"] || [mn isEqualToString:@"store"]) && ops.count >= 2) {
        return [NSString stringWithFormat:@"%@ = %@;%@", ops[1], ops[0], comment];
    }
    NSDictionary<NSString *, NSString *> *binary = @{
        @"add": @"+", @"sub": @"-", @"imul": @"*", @"mul": @"*", @"and": @"&", @"or": @"|", @"xor": @"^",
        @"shl": @"<<", @"sal": @"<<", @"shr": @">>", @"sar": @">>", @"lsl": @"<<", @"lsr": @">>"
    };
    NSString *op = binary[mn];
    if (op && ops.count >= 2) {
        NSString *lhs = ops.count >= 3 ? ops[1] : ops[0];
        NSString *rhs = ops.count >= 3 ? ops[2] : ops[1];
        return [NSString stringWithFormat:@"%@ = %@ %@ %@;%@", ops[0], lhs, op, rhs, comment];
    }
    if (([mn isEqualToString:@"cmp"] || [mn isEqualToString:@"test"] || [mn isEqualToString:@"tst"]) && ops.count >= 2) {
        return [NSString stringWithFormat:@"flags = compare(%@, %@);%@", ops[0], ops[1], comment];
    }
    if ([mn isEqualToString:@"push"] && ops.count >= 1) {
        return [NSString stringWithFormat:@"push(%@);%@", ops[0], comment];
    }
    if ([mn isEqualToString:@"pop"] && ops.count >= 1) {
        return [NSString stringWithFormat:@"%@ = pop();%@", ops[0], comment];
    }
    if ([mn isEqualToString:@"call"] || [mn isEqualToString:@"bl"] || [mn isEqualToString:@"blr"]) {
        return [NSString stringWithFormat:@"call(%@);%@", i.operands.length ? i.operands : @"indirect", comment];
    }
    if ([self isConditionalJump:mn]) {
        return [NSString stringWithFormat:@"if (%@) goto %@;%@", [self conditionForJump:mn], [self sanitizedTarget:i.operands], comment];
    }
    if ([mn isEqualToString:@"jmp"] || [mn isEqualToString:@"b"]) {
        return [NSString stringWithFormat:@"goto %@;%@", [self sanitizedTarget:i.operands], comment];
    }
    if ([mn isEqualToString:@"bx"] && [i.operands.lowercaseString isEqualToString:@"lr"]) {
        return [NSString stringWithFormat:@"return;%@", comment];
    }
    if ([self isReturn:mn]) {
        return [NSString stringWithFormat:@"return;%@", comment];
    }
    if ([mn isEqualToString:@"nop"]) {
        return [NSString stringWithFormat:@"/* nop */%@", comment];
    }
    return [NSString stringWithFormat:@"asm(\"%@ %@\");%@", i.mnemonic, i.operands, comment];
}

- (NSArray<NSString *> *)operandsFromString:(NSString *)operands {
    if (operands.length == 0) return @[];
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    NSMutableString *current = [NSMutableString string];
    NSInteger bracketDepth = 0;
    for (NSUInteger i = 0; i < operands.length; i++) {
        unichar c = [operands characterAtIndex:i];
        if (c == '[' || c == '(' || c == '{') bracketDepth++;
        if (c == ']' || c == ')' || c == '}') bracketDepth--;
        if (c == ',' && bracketDepth == 0) {
            [parts addObject:[current stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet]];
            [current setString:@""];
        } else {
            [current appendFormat:@"%C", c];
        }
    }
    if (current.length) {
        [parts addObject:[current stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet]];
    }
    return parts;
}

- (BOOL)isReturn:(NSString *)mnemonic {
    NSString *m = mnemonic.lowercaseString;
    return [m isEqualToString:@"ret"] || [m isEqualToString:@"retq"] || [m isEqualToString:@"eret"];
}

- (BOOL)isReturnInstruction:(DCInstruction *)instruction {
    NSString *mnemonic = instruction.mnemonic.lowercaseString;
    NSString *operands = instruction.operands.lowercaseString;
    return [self isReturn:mnemonic] || ([mnemonic isEqualToString:@"bx"] && [operands isEqualToString:@"lr"]);
}

- (BOOL)isConditionalJump:(NSString *)mnemonic {
    NSString *m = mnemonic.lowercaseString;
    if ([m hasPrefix:@"j"] && ![m isEqualToString:@"jmp"]) return YES;
    return [@[@"cbz", @"cbnz", @"tbz", @"tbnz", @"beq", @"bne", @"bgt", @"bge", @"blt", @"ble", @"bhi", @"bls"] containsObject:m];
}

- (NSString *)conditionForJump:(NSString *)mnemonic {
    NSDictionary<NSString *, NSString *> *conditions = @{
        @"je": @"flags.equal", @"jz": @"flags.zero", @"jne": @"!flags.equal", @"jnz": @"!flags.zero",
        @"jg": @"flags.greater", @"jge": @"flags.greater_or_equal", @"jl": @"flags.less", @"jle": @"flags.less_or_equal",
        @"ja": @"flags.above", @"jae": @"flags.above_or_equal", @"jb": @"flags.below", @"jbe": @"flags.below_or_equal",
        @"jo": @"flags.overflow", @"jno": @"!flags.overflow", @"js": @"flags.sign", @"jns": @"!flags.sign",
        @"jp": @"flags.parity", @"jnp": @"!flags.parity", @"cbz": @"register_is_zero", @"cbnz": @"register_is_not_zero",
        @"tbz": @"bit_is_zero", @"tbnz": @"bit_is_not_zero", @"beq": @"flags.equal", @"bne": @"!flags.equal",
        @"bgt": @"flags.greater", @"bge": @"flags.greater_or_equal", @"blt": @"flags.less", @"ble": @"flags.less_or_equal",
    };
    return conditions[mnemonic.lowercaseString] ?: [NSString stringWithFormat:@"condition_%@", mnemonic];
}

- (NSString *)sanitizedTarget:(NSString *)target {
    NSString *trimmed = [target stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (trimmed.length == 0) return @"unknown_target";
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"];
    NSMutableString *out = [NSMutableString stringWithString:@"label_"];
    for (NSUInteger i = 0; i < trimmed.length; i++) {
        unichar c = [trimmed characterAtIndex:i];
        [out appendFormat:@"%C", (unichar)([allowed characterIsMember:c] ? c : '_')];
    }
    return out;
}

@end
