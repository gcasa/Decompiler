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

@interface DCLogicalStatement : NSObject
@property (nonatomic) uint64_t address;
@property (nonatomic, copy) NSString *line;
@property (nonatomic, copy) NSString *condition;
@property (nonatomic, copy) NSString *targetLabel;
@property (nonatomic) uint64_t targetAddress;
@property (nonatomic) BOOL conditionalBranch;
@property (nonatomic) BOOL unconditionalBranch;
@property (nonatomic) BOOL returns;
@end

@implementation DCLogicalStatement
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
    return [self renderLogicalC:instructions name:name compact:NO];
}

- (NSString *)renderCompactC:(NSArray<DCInstruction *> *)instructions name:(NSString *)name {
    return [self renderLogicalC:instructions name:name compact:YES];
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

- (NSString *)renderLogicalC:(NSArray<DCInstruction *> *)instructions name:(NSString *)name compact:(BOOL)compact {
    NSMutableString *out = [NSMutableString stringWithFormat:@"%@int function_entry(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {\n",
                            compact ? @"" : [NSString stringWithFormat:@"// Decompiled logic for %@\n", name]];
    NSArray<DCLogicalStatement *> *statements = [self logicalStatementsForInstructions:instructions compact:compact];
    if (statements.count == 0) {
        [out appendString:@"    /* No high-level side effects were recovered from the decoded entry block. */\n"];
        [out appendString:@"    return result;\n}\n"];
        return out;
    }
    NSMutableDictionary<NSNumber *, NSNumber *> *addressToIndex = [NSMutableDictionary dictionary];
    for (NSUInteger i = 0; i < statements.count; i++) {
        addressToIndex[@(statements[i].address)] = @(i);
    }
    [self appendStructuredStatements:statements
                               from:0
                                 to:statements.count
                             indent:1
                                 out:out
                      addressToIndex:addressToIndex];
    if (![out hasSuffix:@"}\n"]) {
        [out appendString:@"}\n"];
    }
    return out;
}

- (NSArray<DCLogicalStatement *> *)logicalStatementsForInstructions:(NSArray<DCInstruction *> *)instructions compact:(BOOL)compact {
    NSMutableDictionary<NSString *, NSString *> *state = [NSMutableDictionary dictionary];
    [self seedInitialRegisterState:state];
    NSMutableSet<NSString *> *declared = [NSMutableSet setWithArray:@[@"arg0", @"arg1", @"arg2", @"arg3", @"result"]];
    __block NSString *lastComparison = nil;
    NSMutableArray<DCLogicalStatement *> *statements = [NSMutableArray array];

    [instructions enumerateObjectsUsingBlock:^(DCInstruction *instruction, NSUInteger idx, BOOL *stop) {
        DCLogicalStatement *statement = [DCLogicalStatement new];
        statement.address = instruction.address;
        NSString *mn = instruction.mnemonic.lowercaseString;
        NSArray<NSString *> *ops = [self operandsFromString:instruction.operands];

        if ([self isConditionalJump:mn]) {
            statement.conditionalBranch = YES;
            statement.condition = [self logicalConditionForJumpInstruction:instruction operands:ops state:state comparison:lastComparison];
            statement.targetAddress = [self targetAddressFromOperand:ops.lastObject ?: instruction.operands];
            statement.targetLabel = [self sanitizedTarget:ops.lastObject ?: instruction.operands];
            [statements addObject:statement];
            return;
        }
        if ([self isUnconditionalJump:mn]) {
            statement.unconditionalBranch = YES;
            statement.targetAddress = [self targetAddressFromOperand:instruction.operands];
            statement.targetLabel = [self sanitizedTarget:instruction.operands];
            [statements addObject:statement];
            return;
        }

        NSString *line = [self logicalLineForInstruction:instruction
                                                   state:state
                                                declared:declared
                                          lastComparison:&lastComparison
                                                 compact:compact];
        if (line.length > 0) {
            statement.line = line;
            [statements addObject:statement];
        } else if (![self isReturnInstruction:instruction]) {
            [statements addObject:statement];
        }
        if ([self isReturnInstruction:instruction]) {
            DCLogicalStatement *returnStatement = [DCLogicalStatement new];
            returnStatement.address = instruction.address;
            returnStatement.returns = YES;
            NSString *resultExpr = [self expressionForRegisterResultFromState:state];
            if (resultExpr.length > 0 && ![resultExpr isEqualToString:@"result"]) {
                returnStatement.line = [NSString stringWithFormat:@"return %@;", resultExpr];
            } else {
                returnStatement.line = @"return result;";
            }
            [statements addObject:returnStatement];
            *stop = YES;
        }
    }];
    if (statements.count == 0 || !statements.lastObject.returns) {
        DCLogicalStatement *returnStatement = [DCLogicalStatement new];
        returnStatement.address = instructions.lastObject.address;
        returnStatement.returns = YES;
        NSString *resultExpr = [self expressionForRegisterResultFromState:state];
        returnStatement.line = [NSString stringWithFormat:@"return %@;", resultExpr.length ? resultExpr : @"result"];
        [statements addObject:returnStatement];
    }
    return statements;
}

- (NSUInteger)appendStructuredStatements:(NSArray<DCLogicalStatement *> *)statements
                                    from:(NSUInteger)start
                                      to:(NSUInteger)end
                                  indent:(NSUInteger)indent
                                      out:(NSMutableString *)out
                           addressToIndex:(NSDictionary<NSNumber *, NSNumber *> *)addressToIndex {
    NSUInteger i = start;
    while (i < end) {
        NSUInteger loopEnd = [self backwardConditionalBranchIndexTargetingIndex:i
                                                                     statements:statements
                                                                           from:i
                                                                             to:end
                                                                 addressToIndex:addressToIndex];
        if (loopEnd != NSNotFound && loopEnd > i) {
            DCLogicalStatement *backEdge = statements[loopEnd];
            [self appendIndent:indent to:out];
            [out appendString:@"do {\n"];
            [self appendStructuredStatements:statements from:i to:loopEnd indent:indent + 1 out:out addressToIndex:addressToIndex];
            [self appendIndent:indent to:out];
            [out appendFormat:@"} while (%@);\n", backEdge.condition ?: @"condition"];
            i = loopEnd + 1;
            continue;
        }

        DCLogicalStatement *statement = statements[i];

        if (statement.conditionalBranch) {
            NSNumber *targetNumber = addressToIndex[@(statement.targetAddress)];
            NSUInteger targetIndex = targetNumber ? targetNumber.unsignedIntegerValue : NSNotFound;
            if (targetIndex != NSNotFound && targetIndex > i && targetIndex <= end) {
                NSUInteger thenEnd = targetIndex;
                DCLogicalStatement *beforeTarget = targetIndex > i + 1 ? statements[targetIndex - 1] : nil;
                NSNumber *afterElseNumber = beforeTarget.unconditionalBranch ? addressToIndex[@(beforeTarget.targetAddress)] : nil;
                NSUInteger afterElseIndex = afterElseNumber ? afterElseNumber.unsignedIntegerValue : NSNotFound;

                if (beforeTarget.unconditionalBranch && afterElseIndex != NSNotFound && afterElseIndex > targetIndex && afterElseIndex <= end) {
                    thenEnd = targetIndex - 1;
                    [self appendIndent:indent to:out];
                    [out appendFormat:@"if (%@) {\n", [self negatedCondition:statement.condition]];
                    [self appendStructuredStatements:statements from:i + 1 to:thenEnd indent:indent + 1 out:out addressToIndex:addressToIndex];
                    [self appendIndent:indent to:out];
                    [out appendString:@"} else {\n"];
                    [self appendStructuredStatements:statements from:targetIndex to:afterElseIndex indent:indent + 1 out:out addressToIndex:addressToIndex];
                    [self appendIndent:indent to:out];
                    [out appendString:@"}\n"];
                    i = afterElseIndex;
                    continue;
                }

                [self appendIndent:indent to:out];
                [out appendFormat:@"if (%@) {\n", [self negatedCondition:statement.condition]];
                [self appendStructuredStatements:statements from:i + 1 to:targetIndex indent:indent + 1 out:out addressToIndex:addressToIndex];
                [self appendIndent:indent to:out];
                [out appendString:@"}\n"];
                i = targetIndex;
                continue;
            }

            if (targetIndex != NSNotFound && targetIndex < i) {
                [self appendIndent:indent to:out];
                [out appendFormat:@"if (%@) {\n", statement.condition];
                [self appendIndent:indent + 1 to:out];
                [out appendFormat:@"continue; /* loop back to %@ */\n", statement.targetLabel ?: @"earlier block"];
                [self appendIndent:indent to:out];
                [out appendString:@"}\n"];
                i++;
                continue;
            }
            [self appendIndent:indent to:out];
            [out appendFormat:@"if (%@) goto %@;\n", statement.condition ?: @"condition", statement.targetLabel ?: @"unknown_target"];
            i++;
            continue;
        }

        if (statement.unconditionalBranch) {
            NSNumber *targetNumber = addressToIndex[@(statement.targetAddress)];
            NSUInteger targetIndex = targetNumber ? targetNumber.unsignedIntegerValue : NSNotFound;
            if (targetIndex != NSNotFound && targetIndex < i) {
                [self appendIndent:indent to:out];
                [out appendFormat:@"while (true) { /* back edge to %@ */\n", statement.targetLabel ?: @"earlier block"];
                [self appendIndent:indent + 1 to:out];
                [out appendString:@"break; /* loop body is above in linearized output */\n"];
                [self appendIndent:indent to:out];
                [out appendString:@"}\n"];
                i++;
                continue;
            }
            if (targetIndex != NSNotFound && targetIndex == i + 1) {
                i++;
                continue;
            }
            [self appendIndent:indent to:out];
            [out appendFormat:@"goto %@;\n", statement.targetLabel ?: @"unknown_target"];
            i++;
            continue;
        }

        if (statement.line.length > 0) {
            [self appendIndent:indent to:out];
            [out appendFormat:@"%@\n", statement.line];
        }
        i++;
    }
    return i;
}

- (NSUInteger)backwardConditionalBranchIndexTargetingIndex:(NSUInteger)targetIndex
                                                statements:(NSArray<DCLogicalStatement *> *)statements
                                                      from:(NSUInteger)start
                                                        to:(NSUInteger)end
                                            addressToIndex:(NSDictionary<NSNumber *, NSNumber *> *)addressToIndex {
    if (targetIndex >= statements.count) return NSNotFound;
    uint64_t targetAddress = statements[targetIndex].address;
    for (NSUInteger i = start + 1; i < end; i++) {
        DCLogicalStatement *candidate = statements[i];
        if (!candidate.conditionalBranch || candidate.targetAddress != targetAddress) {
            continue;
        }
        NSNumber *mapped = addressToIndex[@(candidate.targetAddress)];
        if (mapped && mapped.unsignedIntegerValue == targetIndex) {
            return i;
        }
    }
    return NSNotFound;
}

- (NSString *)negatedCondition:(NSString *)condition {
    NSString *c = condition ?: @"condition";
    NSArray<NSArray<NSString *> *> *pairs = @[
        @[@" <= 0", @" > 0"],
        @[@" >= 0", @" < 0"],
        @[@" == 0", @" != 0"],
        @[@" != 0", @" == 0"],
        @[@" < 0", @" >= 0"],
        @[@" > 0", @" <= 0"],
    ];
    for (NSArray<NSString *> *pair in pairs) {
        NSString *from = pair[0];
        NSString *to = pair[1];
        if ([c hasSuffix:from]) {
            return [[c substringToIndex:c.length - from.length] stringByAppendingString:to];
        }
    }
    return [NSString stringWithFormat:@"!(%@)", c];
}

- (void)appendIndent:(NSUInteger)indent to:(NSMutableString *)out {
    for (NSUInteger i = 0; i < indent; i++) {
        [out appendString:@"    "];
    }
}

- (BOOL)isUnconditionalJump:(NSString *)mnemonic {
    NSString *m = [mnemonic.lowercaseString stringByReplacingOccurrencesOfString:@"." withString:@""];
    return [m isEqualToString:@"jmp"] || [m isEqualToString:@"b"];
}

- (uint64_t)targetAddressFromOperand:(NSString *)operand {
    NSString *trimmed = [[operand stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] lowercaseString];
    trimmed = [trimmed stringByReplacingOccurrencesOfString:@"#" withString:@""];
    NSScanner *scanner = [NSScanner scannerWithString:trimmed];
    unsigned long long value = 0;
    if ([trimmed hasPrefix:@"0x"]) {
        return [scanner scanHexLongLong:&value] ? value : 0;
    }
    return [scanner scanUnsignedLongLong:&value] ? value : 0;
}

- (NSString *)logicalLineForInstruction:(DCInstruction *)instruction
                                  state:(NSMutableDictionary<NSString *, NSString *> *)state
                               declared:(NSMutableSet<NSString *> *)declared
                         lastComparison:(NSString **)lastComparison
                                compact:(BOOL)compact {
    NSString *mn = instruction.mnemonic.lowercaseString;
    NSArray<NSString *> *ops = [self operandsFromString:instruction.operands];
    NSString *comment = compact ? @"" : [NSString stringWithFormat:@" // 0x%llx", instruction.address];

    if ([mn isEqualToString:@"nop"] || [self isFrameSetupInstruction:instruction operands:ops]) {
        return @"";
    }
    if ([self isReturnInstruction:instruction]) {
        return @"";
    }

    if (([mn isEqualToString:@"mov"] || [mn isEqualToString:@"movz"] || [mn isEqualToString:@"movn"] ||
         [mn isEqualToString:@"movsx"] || [mn isEqualToString:@"movsxd"] || [mn isEqualToString:@"movzx"] ||
         [mn isEqualToString:@"adr"] || [mn isEqualToString:@"adrp"] || [mn isEqualToString:@"lea"]) && ops.count >= 2) {
        NSString *dest = ops[0];
        NSString *expr = [self logicalExpressionForOperand:ops[1] state:state];
        return [self assignLogicalExpression:expr toOperand:dest state:state declared:declared comment:comment];
    }

    if (([mn hasPrefix:@"ldr"] || [mn isEqualToString:@"load"]) && ops.count >= 2) {
        NSString *slot = [self stackSlotNameForOperand:ops[1]];
        NSString *expr = slot ?: [self logicalMemoryExpressionForOperand:ops[1] state:state];
        return [self assignLogicalExpression:expr toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if (([mn hasPrefix:@"str"] || [mn isEqualToString:@"store"]) && ops.count >= 2) {
        NSString *value = [self logicalExpressionForOperand:ops[0] state:state];
        NSString *slot = [self stackSlotNameForOperand:ops[1]];
        if (slot.length > 0) {
            NSString *prefix = [declared containsObject:slot] ? @"" : @"uint64_t ";
            [declared addObject:slot];
            return [NSString stringWithFormat:@"%@%@ = %@;%@", prefix, slot, value, comment];
        }
        NSString *target = [self logicalMemoryExpressionForOperand:ops[1] state:state];
        return [NSString stringWithFormat:@"%@ = %@;%@", target, value, comment];
    }

    if ([mn isEqualToString:@"ldp"] && ops.count >= 3) {
        NSString *base = [self logicalMemoryExpressionForOperand:ops[2] state:state];
        [self assignLogicalExpression:[NSString stringWithFormat:@"%@.first", base] toOperand:ops[0] state:state declared:declared comment:@""];
        [self assignLogicalExpression:[NSString stringWithFormat:@"%@.second", base] toOperand:ops[1] state:state declared:declared comment:@""];
        return [NSString stringWithFormat:@"/* recovered pair load from %@ */%@", base, comment];
    }

    if ([mn isEqualToString:@"stp"] && ops.count >= 3) {
        NSString *target = [self logicalMemoryExpressionForOperand:ops[2] state:state];
        NSString *first = [self logicalExpressionForOperand:ops[0] state:state];
        NSString *second = [self logicalExpressionForOperand:ops[1] state:state];
        return [NSString stringWithFormat:@"store_pair(%@, %@, %@);%@", target, first, second, comment];
    }

    NSDictionary<NSString *, NSString *> *binary = @{
        @"add": @"+", @"adds": @"+", @"adc": @"+", @"sub": @"-", @"subs": @"-", @"sbb": @"-",
        @"imul": @"*", @"mul": @"*", @"and": @"&", @"ands": @"&", @"bic": @"& ~", @"orr": @"|", @"or": @"|",
        @"eor": @"^", @"xor": @"^", @"shl": @"<<", @"sal": @"<<", @"shr": @">>", @"sar": @">>", @"lsl": @"<<", @"lsr": @">>", @"asr": @">>"
    };
    NSString *op = binary[mn];
    if (op && ops.count >= 2) {
        NSString *dest = ops[0];
        NSString *lhs = [self logicalExpressionForOperand:(ops.count >= 3 ? ops[1] : ops[0]) state:state];
        NSString *rhs = [self logicalExpressionForOperand:(ops.count >= 3 ? ops[2] : ops[1]) state:state];
        NSString *expr = [NSString stringWithFormat:@"(%@ %@ %@)", lhs, op, rhs];
        if ([mn hasSuffix:@"s"]) {
            *lastComparison = [NSString stringWithFormat:@"compare(%@, 0)", expr];
        }
        return [self assignLogicalExpression:expr toOperand:dest state:state declared:declared comment:comment];
    }

    if ([mn isEqualToString:@"madd"] && ops.count >= 4) {
        NSString *expr = [NSString stringWithFormat:@"((%@ * %@) + %@)",
                          [self logicalExpressionForOperand:ops[1] state:state],
                          [self logicalExpressionForOperand:ops[2] state:state],
                          [self logicalExpressionForOperand:ops[3] state:state]];
        return [self assignLogicalExpression:expr toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if (([mn isEqualToString:@"udiv"] || [mn isEqualToString:@"sdiv"]) && ops.count >= 3) {
        NSString *expr = [NSString stringWithFormat:@"(%@ / %@)",
                          [self logicalExpressionForOperand:ops[1] state:state],
                          [self logicalExpressionForOperand:ops[2] state:state]];
        return [self assignLogicalExpression:expr toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if (([mn isEqualToString:@"inc"] || [mn isEqualToString:@"dec"]) && ops.count >= 1) {
        NSString *old = [self logicalExpressionForOperand:ops[0] state:state];
        NSString *expr = [NSString stringWithFormat:@"(%@ %@ 1)", old, [mn isEqualToString:@"inc"] ? @"+" : @"-"];
        *lastComparison = [NSString stringWithFormat:@"compare(%@, 0)", expr];
        return [self assignLogicalExpression:expr toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if (([mn isEqualToString:@"neg"] || [mn isEqualToString:@"not"]) && ops.count >= 1) {
        NSString *expr = [NSString stringWithFormat:@"%@%@", [mn isEqualToString:@"neg"] ? @"-" : @"~", [self logicalExpressionForOperand:ops[0] state:state]];
        return [self assignLogicalExpression:expr toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if (([mn isEqualToString:@"cmp"] || [mn isEqualToString:@"test"] || [mn isEqualToString:@"tst"]) && ops.count >= 2) {
        NSString *lhs = [self logicalExpressionForOperand:ops[0] state:state];
        NSString *rhs = [self logicalExpressionForOperand:ops[1] state:state];
        *lastComparison = [NSString stringWithFormat:@"compare(%@, %@)", lhs, rhs];
        return @"";
    }

    if ([mn hasPrefix:@"cmov"] && ops.count >= 2) {
        NSString *condition = [self logicalConditionForCode:[mn substringFromIndex:4] comparison:*lastComparison];
        NSString *expr = [NSString stringWithFormat:@"(%@ ? %@ : %@)", condition, [self logicalExpressionForOperand:ops[1] state:state], [self logicalExpressionForOperand:ops[0] state:state]];
        return [self assignLogicalExpression:expr toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if ([mn hasPrefix:@"set"] && ops.count >= 1) {
        NSString *condition = [self logicalConditionForCode:[mn substringFromIndex:3] comparison:*lastComparison];
        return [self assignLogicalExpression:[NSString stringWithFormat:@"(%@ ? 1 : 0)", condition] toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if ([mn hasPrefix:@"cset"] && ops.count >= 1) {
        NSString *condition = ops.count >= 2 ? [NSString stringWithFormat:@"condition_%@", [self sanitizedIdentifierFromString:ops[1] prefix:@""]] : @"condition";
        return [self assignLogicalExpression:[NSString stringWithFormat:@"(%@ ? 1 : 0)", condition] toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if ([mn isEqualToString:@"csel"] && ops.count >= 4) {
        NSString *condition = [self logicalConditionForCode:ops[3] comparison:*lastComparison];
        NSString *expr = [NSString stringWithFormat:@"(%@ ? %@ : %@)",
                          condition,
                          [self logicalExpressionForOperand:ops[1] state:state],
                          [self logicalExpressionForOperand:ops[2] state:state]];
        return [self assignLogicalExpression:expr toOperand:ops[0] state:state declared:declared comment:comment];
    }

    if ([mn isEqualToString:@"call"] || [mn isEqualToString:@"bl"] || [mn isEqualToString:@"blr"]) {
        NSString *target = instruction.operands.length ? instruction.operands : @"indirect";
        NSString *line = [NSString stringWithFormat:@"result = %@(%@, %@, %@, %@);%@",
                          [self sanitizedCallTarget:target],
                          [self callArgumentExpressionAtIndex:0 state:state],
                          [self callArgumentExpressionAtIndex:1 state:state],
                          [self callArgumentExpressionAtIndex:2 state:state],
                          [self callArgumentExpressionAtIndex:3 state:state],
                          comment];
        state[@"x0"] = @"result";
        state[@"w0"] = @"result";
        state[@"rax"] = @"result";
        state[@"eax"] = @"result";
        return line;
    }

    if ([mn isEqualToString:@"svc"] || [mn isEqualToString:@"syscall"] || [mn isEqualToString:@"int"]) {
        return [NSString stringWithFormat:@"result = system_call(arg0, arg1, arg2, arg3);%@", comment];
    }

    if ([self isConditionalJump:mn]) {
        NSString *condition = [self logicalConditionForJumpInstruction:instruction operands:ops state:state comparison:*lastComparison];
        return [NSString stringWithFormat:@"if (%@) goto %@;%@", condition, [self sanitizedTarget:ops.lastObject ?: instruction.operands], comment];
    }

    if ([mn isEqualToString:@"jmp"] || [mn isEqualToString:@"b"]) {
        return [NSString stringWithFormat:@"goto %@;%@", [self sanitizedTarget:instruction.operands], comment];
    }

    if ([mn isEqualToString:@"push"] || [mn isEqualToString:@"pop"] || [mn isEqualToString:@"leave"]) {
        return @"";
    }

    return [NSString stringWithFormat:@"%@;%@", [self semanticFallbackForInstruction:instruction operands:ops], comment];
}

- (BOOL)isFrameSetupInstruction:(DCInstruction *)instruction operands:(NSArray<NSString *> *)ops {
    NSString *mn = instruction.mnemonic.lowercaseString;
    if ([mn isEqualToString:@"push"] && ops.count == 1) {
        NSString *op = ops[0].lowercaseString;
        return [op isEqualToString:@"rbp"] || [op isEqualToString:@"ebp"] || [op isEqualToString:@"fp"] || [op isEqualToString:@"x29"];
    }
    if ([mn isEqualToString:@"mov"] && ops.count >= 2) {
        NSString *dst = ops[0].lowercaseString;
        NSString *src = ops[1].lowercaseString;
        return (([dst isEqualToString:@"rbp"] || [dst isEqualToString:@"ebp"]) && ([src isEqualToString:@"rsp"] || [src isEqualToString:@"esp"]));
    }
    if (([mn isEqualToString:@"sub"] || [mn isEqualToString:@"add"]) && ops.count >= 2) {
        NSString *dst = ops[0].lowercaseString;
        return [dst isEqualToString:@"sp"] || [dst isEqualToString:@"rsp"] || [dst isEqualToString:@"esp"];
    }
    if ([mn isEqualToString:@"stp"] && ops.count >= 3) {
        NSString *first = ops[0].lowercaseString;
        NSString *second = ops[1].lowercaseString;
        NSString *where = ops[2].lowercaseString;
        return ([first isEqualToString:@"x29"] && [second isEqualToString:@"x30"] && [where containsString:@"sp"]);
    }
    if ([mn isEqualToString:@"mov"] && ops.count >= 2) {
        return [ops[0].lowercaseString isEqualToString:@"x29"] && [ops[1].lowercaseString isEqualToString:@"sp"];
    }
    return NO;
}

- (NSString *)assignLogicalExpression:(NSString *)expr
                             toOperand:(NSString *)operand
                                 state:(NSMutableDictionary<NSString *, NSString *> *)state
                              declared:(NSMutableSet<NSString *> *)declared
                               comment:(NSString *)comment {
    NSString *trimmed = [operand stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if ([self isRegisterOperand:trimmed]) {
        NSString *reg = [self canonicalRegister:trimmed];
        NSString *name = [self variableNameForRegister:reg];
        if ([self shouldSuppressTemporaryRegister:reg expression:expr]) {
            state[reg] = expr;
            return @"";
        }
        state[reg] = name;
        NSString *prefix = [declared containsObject:name] ? @"" : @"uint64_t ";
        [declared addObject:name];
        return [NSString stringWithFormat:@"%@%@ = %@;%@", prefix, name, expr, comment];
    }

    NSString *target = [self logicalMemoryExpressionForOperand:trimmed state:state];
    return [NSString stringWithFormat:@"%@ = %@;%@", target, expr, comment];
}

- (BOOL)shouldSuppressTemporaryRegister:(NSString *)reg expression:(NSString *)expr {
    if ([reg hasPrefix:@"sp"] || [reg hasPrefix:@"rsp"] || [reg hasPrefix:@"esp"] ||
        [reg hasPrefix:@"fp"] || [reg hasPrefix:@"rbp"] || [reg hasPrefix:@"ebp"] ||
        [reg isEqualToString:@"x29"] || [reg isEqualToString:@"x30"] || [reg isEqualToString:@"lr"]) {
        return YES;
    }
    return NO;
}

- (NSString *)logicalExpressionForOperand:(NSString *)operand state:(NSDictionary<NSString *, NSString *> *)state {
    NSString *trimmed = [operand stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (trimmed.length == 0) {
        return @"unknown";
    }
    if ([self isRegisterOperand:trimmed]) {
        NSString *reg = [self canonicalRegister:trimmed];
        return state[reg] ?: [self variableNameForRegister:reg];
    }
    if ([trimmed hasPrefix:@"#"]) {
        return [trimmed substringFromIndex:1];
    }
    if ([trimmed hasPrefix:@"["] || [trimmed containsString:@" ptr "]) {
        return [self logicalMemoryExpressionForOperand:trimmed state:state];
    }
    return [self sanitizedLiteralExpression:trimmed];
}

- (NSString *)logicalMemoryExpressionForOperand:(NSString *)operand state:(NSDictionary<NSString *, NSString *> *)state {
    NSString *trimmed = [operand stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSString *inner = trimmed;
    NSRange bracketStart = [inner rangeOfString:@"["];
    NSRange bracketEnd = [inner rangeOfString:@"]" options:NSBackwardsSearch];
    if (bracketStart.location != NSNotFound && bracketEnd.location != NSNotFound && bracketEnd.location > bracketStart.location) {
        inner = [inner substringWithRange:NSMakeRange(bracketStart.location + 1, bracketEnd.location - bracketStart.location - 1)];
    }
    inner = [inner stringByReplacingOccurrencesOfString:@"#" withString:@""];
    inner = [inner stringByReplacingOccurrencesOfString:@"," withString:@" +"];
    NSArray<NSString *> *tokens = [inner componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (NSString *token in tokens) {
        NSString *part = [token stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (part.length == 0 || [part isEqualToString:@"+"]) continue;
        if ([self isRegisterOperand:part]) {
            [parts addObject:[self logicalExpressionForOperand:part state:state]];
        } else {
            [parts addObject:[self sanitizedLiteralExpression:part]];
        }
    }
    NSString *address = parts.count ? [parts componentsJoinedByString:@" + "] : [self sanitizedLiteralExpression:trimmed];
    return [NSString stringWithFormat:@"*((uint64_t *)(%@))", address];
}

- (NSString *)expressionForRegisterResultFromState:(NSDictionary<NSString *, NSString *> *)state {
    for (NSString *reg in @[@"w0", @"x0", @"eax", @"rax", @"r0"]) {
        NSString *expr = state[reg];
        if (expr.length > 0) return expr;
    }
    return @"result";
}

- (NSString *)stackSlotNameForOperand:(NSString *)operand {
    NSString *lower = operand.lowercaseString;
    if (!([lower containsString:@"sp"] || [lower containsString:@"rsp"] || [lower containsString:@"esp"] ||
          [lower containsString:@"fp"] || [lower containsString:@"rbp"] || [lower containsString:@"ebp"])) {
        return nil;
    }
    NSRegularExpression *hexRegex = [NSRegularExpression regularExpressionWithPattern:@"0x[0-9a-f]+" options:0 error:nil];
    NSTextCheckingResult *hex = [hexRegex firstMatchInString:lower options:0 range:NSMakeRange(0, lower.length)];
    NSString *offset = nil;
    if (hex) {
        offset = [lower substringWithRange:hex.range];
    } else {
        NSRegularExpression *decRegex = [NSRegularExpression regularExpressionWithPattern:@"[+-]?\\b[0-9]+\\b" options:0 error:nil];
        NSTextCheckingResult *dec = [decRegex firstMatchInString:lower options:0 range:NSMakeRange(0, lower.length)];
        if (dec) offset = [lower substringWithRange:dec.range];
    }
    if (offset.length == 0) {
        offset = @"0";
    }
    offset = [offset stringByReplacingOccurrencesOfString:@"-" withString:@"neg_"];
    offset = [offset stringByReplacingOccurrencesOfString:@"+" withString:@""];
    offset = [offset stringByReplacingOccurrencesOfString:@"0x" withString:@""];
    return [NSString stringWithFormat:@"local_%@", [self sanitizedIdentifierFromString:offset prefix:@""]];
}

- (NSString *)callArgumentExpressionAtIndex:(NSUInteger)index state:(NSDictionary<NSString *, NSString *> *)state {
    NSArray<NSArray<NSString *> *> *sets = @[
        @[@"x0", @"w0", @"rdi", @"edi", @"r0"],
        @[@"x1", @"w1", @"rsi", @"esi", @"r1"],
        @[@"x2", @"w2", @"rdx", @"edx", @"r2"],
        @[@"x3", @"w3", @"rcx", @"ecx", @"r3"],
    ];
    if (index >= sets.count) return [NSString stringWithFormat:@"arg%lu", (unsigned long)index];
    for (NSString *reg in sets[index]) {
        NSString *expr = state[reg];
        if (expr.length > 0) return expr;
    }
    return [NSString stringWithFormat:@"arg%lu", (unsigned long)index];
}

- (NSString *)logicalConditionForJumpInstruction:(DCInstruction *)instruction
                                       operands:(NSArray<NSString *> *)ops
                                          state:(NSDictionary<NSString *, NSString *> *)state
                                     comparison:(NSString *)comparison {
    NSString *mn = instruction.mnemonic.lowercaseString;
    mn = [mn stringByReplacingOccurrencesOfString:@"." withString:@""];
    if (([mn isEqualToString:@"cbz"] || [mn isEqualToString:@"cbnz"]) && ops.count >= 2) {
        NSString *expr = [self logicalExpressionForOperand:ops[0] state:state];
        return [NSString stringWithFormat:@"%@ %@ 0", expr, [mn isEqualToString:@"cbz"] ? @"==" : @"!="];
    }
    if (([mn isEqualToString:@"tbz"] || [mn isEqualToString:@"tbnz"]) && ops.count >= 3) {
        NSString *expr = [self logicalExpressionForOperand:ops[0] state:state];
        NSString *bit = [self logicalExpressionForOperand:ops[1] state:state];
        return [NSString stringWithFormat:@"((%@ & (1ULL << %@)) %@ 0)", expr, bit, [mn isEqualToString:@"tbz"] ? @"==" : @"!="];
    }
    NSString *code = mn;
    if ([code hasPrefix:@"j"]) code = [code substringFromIndex:1];
    if ([code hasPrefix:@"b"] && code.length > 1) code = [code substringFromIndex:1];
    return [self logicalConditionForCode:code comparison:comparison];
}

- (NSString *)logicalConditionForCode:(NSString *)code comparison:(NSString *)comparison {
    NSString *cmp = comparison.length ? comparison : @"compare(lhs, rhs)";
    NSDictionary<NSString *, NSString *> *conditions = @{
        @"e": @"%@ == 0", @"z": @"%@ == 0", @"eq": @"%@ == 0",
        @"ne": @"%@ != 0", @"nz": @"%@ != 0",
        @"g": @"%@ > 0", @"gt": @"%@ > 0",
        @"ge": @"%@ >= 0",
        @"l": @"%@ < 0", @"lt": @"%@ < 0",
        @"le": @"%@ <= 0",
        @"a": @"%@ > 0", @"hi": @"%@ > 0",
        @"ae": @"%@ >= 0", @"hs": @"%@ >= 0",
        @"b": @"%@ < 0", @"lo": @"%@ < 0",
        @"be": @"%@ <= 0", @"ls": @"%@ <= 0",
        @"o": @"overflow", @"no": @"!overflow",
        @"s": @"sign", @"ns": @"!sign",
    };
    NSString *format = conditions[code.lowercaseString];
    if (!format) {
        return [NSString stringWithFormat:@"condition_%@(%@)", [self sanitizedIdentifierFromString:code prefix:@""], cmp];
    }
    if ([format containsString:@"%@"]) {
        return [NSString stringWithFormat:format, cmp];
    }
    return format;
}

- (NSString *)sanitizedCallTarget:(NSString *)target {
    NSString *trimmed = [target stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (trimmed.length == 0) return @"indirect_call";
    if ([trimmed hasPrefix:@"#"]) trimmed = [trimmed substringFromIndex:1];
    if ([trimmed hasPrefix:@"0x"]) return [NSString stringWithFormat:@"sub_%@", [self sanitizedIdentifierFromString:trimmed prefix:@""]];
    return [self sanitizedIdentifierFromString:trimmed prefix:@"call_"];
}

- (NSString *)sanitizedLiteralExpression:(NSString *)value {
    NSString *trimmed = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    trimmed = [trimmed stringByReplacingOccurrencesOfString:@"#" withString:@""];
    trimmed = [trimmed stringByReplacingOccurrencesOfString:@"$" withString:@""];
    return trimmed.length ? trimmed : @"unknown";
}

- (BOOL)isRegisterOperand:(NSString *)operand {
    NSString *reg = [self canonicalRegister:operand];
    if (reg.length == 0) return NO;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^(x|w|r)[0-9]+$|^(rax|eax|rbx|ebx|rcx|ecx|rdx|edx|rsi|esi|rdi|edi|rsp|esp|rbp|ebp|sp|fp|lr|ip|pc|x29|x30)$"
                                                                           options:0
                                                                             error:nil];
    return [regex firstMatchInString:reg options:0 range:NSMakeRange(0, reg.length)] != nil;
}

- (void)seedInitialRegisterState:(NSMutableDictionary<NSString *, NSString *> *)state {
    NSDictionary<NSString *, NSString *> *initial = @{
        @"x0": @"arg0", @"w0": @"arg0", @"r0": @"arg0", @"rdi": @"arg0", @"edi": @"arg0",
        @"x1": @"arg1", @"w1": @"arg1", @"r1": @"arg1", @"rsi": @"arg1", @"esi": @"arg1",
        @"x2": @"arg2", @"w2": @"arg2", @"r2": @"arg2", @"rdx": @"arg2", @"edx": @"arg2",
        @"x3": @"arg3", @"w3": @"arg3", @"r3": @"arg3", @"rcx": @"arg3", @"ecx": @"arg3",
    };
    [state addEntriesFromDictionary:initial];
}

- (NSString *)canonicalRegister:(NSString *)operand {
    NSString *reg = [[operand stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] lowercaseString];
    reg = [reg stringByReplacingOccurrencesOfString:@"," withString:@""];
    return reg;
}

- (NSString *)variableNameForRegister:(NSString *)reg {
    NSDictionary<NSString *, NSString *> *names = @{
        @"x0": @"tmp_x0", @"w0": @"tmp_w0", @"r0": @"tmp_r0", @"rdi": @"tmp_rdi", @"edi": @"tmp_edi",
        @"x1": @"tmp_x1", @"w1": @"tmp_w1", @"r1": @"tmp_r1", @"rsi": @"tmp_rsi", @"esi": @"tmp_esi",
        @"x2": @"tmp_x2", @"w2": @"tmp_w2", @"r2": @"tmp_r2", @"rdx": @"tmp_rdx", @"edx": @"tmp_edx",
        @"x3": @"tmp_x3", @"w3": @"tmp_w3", @"r3": @"tmp_r3", @"rcx": @"tmp_rcx", @"ecx": @"tmp_ecx",
        @"rax": @"result", @"eax": @"result",
        @"sp": @"stack_pointer", @"rsp": @"stack_pointer", @"esp": @"stack_pointer",
        @"fp": @"frame_pointer", @"rbp": @"frame_pointer", @"ebp": @"frame_pointer", @"x29": @"frame_pointer",
        @"lr": @"return_address", @"x30": @"return_address",
    };
    NSString *name = names[reg];
    if (name) return name;
    return [self sanitizedIdentifierFromString:reg prefix:@"tmp_"];
}

- (NSString *)cLineForInstruction:(DCInstruction *)i compact:(BOOL)compact {
    NSString *mn = i.mnemonic.lowercaseString;
    NSArray<NSString *> *ops = [self operandsFromString:i.operands];
    NSString *comment = compact ? @"" : [NSString stringWithFormat:@" // 0x%llx: %@ %@", i.address, i.mnemonic, i.operands];

    if (([mn isEqualToString:@"mov"] || [mn isEqualToString:@"movz"] || [mn isEqualToString:@"movn"] ||
         [mn isEqualToString:@"movsx"] || [mn isEqualToString:@"movsxd"] || [mn isEqualToString:@"movzx"] ||
         [mn isEqualToString:@"adr"] || [mn isEqualToString:@"adrp"] || [mn isEqualToString:@"lea"]) && ops.count >= 2) {
        return [NSString stringWithFormat:@"%@ = %@;%@", ops[0], ops[1], comment];
    }
    if (([mn hasPrefix:@"ldr"] || [mn isEqualToString:@"load"]) && ops.count >= 2) {
        return [NSString stringWithFormat:@"%@ = load(%@);%@", ops[0], ops[1], comment];
    }
    if (([mn hasPrefix:@"str"] || [mn isEqualToString:@"store"]) && ops.count >= 2) {
        return [NSString stringWithFormat:@"%@ = %@;%@", ops[1], ops[0], comment];
    }
    if (([mn isEqualToString:@"ldp"] || [mn isEqualToString:@"popa"]) && ops.count >= 3) {
        return [NSString stringWithFormat:@"tie(%@, %@) = load_pair(%@);%@", ops[0], ops[1], ops[2], comment];
    }
    if (([mn isEqualToString:@"stp"] || [mn isEqualToString:@"pusha"]) && ops.count >= 3) {
        return [NSString stringWithFormat:@"store_pair(%@, %@, %@);%@", ops[2], ops[0], ops[1], comment];
    }
    NSDictionary<NSString *, NSString *> *binary = @{
        @"add": @"+", @"adds": @"+", @"adc": @"+ carry +", @"sub": @"-", @"subs": @"-", @"sbb": @"- borrow -",
        @"imul": @"*", @"mul": @"*", @"and": @"&", @"ands": @"&", @"bic": @"& ~", @"orr": @"|", @"or": @"|",
        @"eor": @"^", @"xor": @"^", @"shl": @"<<", @"sal": @"<<", @"shr": @">>", @"sar": @">>", @"lsl": @"<<", @"lsr": @">>", @"asr": @">>"
    };
    NSString *op = binary[mn];
    if (op && ops.count >= 2) {
        NSString *lhs = ops.count >= 3 ? ops[1] : ops[0];
        NSString *rhs = ops.count >= 3 ? ops[2] : ops[1];
        NSString *line = [NSString stringWithFormat:@"%@ = %@ %@ %@;", ops[0], lhs, op, rhs];
        if ([mn hasSuffix:@"s"] || [mn isEqualToString:@"cmp"] || [mn isEqualToString:@"test"]) {
            line = [line stringByAppendingFormat:@" flags = update_flags(%@);", ops[0]];
        }
        return [line stringByAppendingString:comment];
    }
    if ([mn isEqualToString:@"madd"] && ops.count >= 4) {
        return [NSString stringWithFormat:@"%@ = (%@ * %@) + %@;%@", ops[0], ops[1], ops[2], ops[3], comment];
    }
    if (([mn isEqualToString:@"udiv"] || [mn isEqualToString:@"sdiv"]) && ops.count >= 3) {
        return [NSString stringWithFormat:@"%@ = %@ / %@;%@", ops[0], ops[1], ops[2], comment];
    }
    if (([mn isEqualToString:@"div"] || [mn isEqualToString:@"idiv"]) && ops.count >= 1) {
        return [NSString stringWithFormat:@"tie(quotient, remainder) = divide(accumulator, %@);%@", ops[0], comment];
    }
    if (([mn isEqualToString:@"inc"] || [mn isEqualToString:@"dec"]) && ops.count >= 1) {
        NSString *opText = [mn isEqualToString:@"inc"] ? @"+" : @"-";
        return [NSString stringWithFormat:@"%@ = %@ %@ 1; flags = update_flags(%@);%@", ops[0], ops[0], opText, ops[0], comment];
    }
    if (([mn isEqualToString:@"neg"] || [mn isEqualToString:@"not"]) && ops.count >= 1) {
        NSString *opText = [mn isEqualToString:@"neg"] ? @"-" : @"~";
        return [NSString stringWithFormat:@"%@ = %@%@; flags = update_flags(%@);%@", ops[0], opText, ops[0], ops[0], comment];
    }
    if (([mn isEqualToString:@"cmp"] || [mn isEqualToString:@"test"] || [mn isEqualToString:@"tst"]) && ops.count >= 2) {
        return [NSString stringWithFormat:@"flags = compare(%@, %@);%@", ops[0], ops[1], comment];
    }
    if ([mn hasPrefix:@"cmov"] && ops.count >= 2) {
        return [NSString stringWithFormat:@"if (%@) %@ = %@;%@", [self conditionForConditionalMove:mn], ops[0], ops[1], comment];
    }
    if ([mn hasPrefix:@"set"] && ops.count >= 1) {
        return [NSString stringWithFormat:@"%@ = %@ ? 1 : 0;%@", ops[0], [self conditionForSet:mn], comment];
    }
    if ([mn hasPrefix:@"cset"] && ops.count >= 1) {
        NSString *condition = ops.count >= 2 ? ops[1] : @"condition";
        return [NSString stringWithFormat:@"%@ = condition_%@ ? 1 : 0;%@", ops[0], condition, comment];
    }
    if ([mn isEqualToString:@"push"] && ops.count >= 1) {
        return [NSString stringWithFormat:@"push(%@);%@", ops[0], comment];
    }
    if ([mn isEqualToString:@"pop"] && ops.count >= 1) {
        return [NSString stringWithFormat:@"%@ = pop();%@", ops[0], comment];
    }
    if ([mn isEqualToString:@"leave"]) {
        return [NSString stringWithFormat:@"stack_frame = restore_caller_frame();%@", comment];
    }
    if ([mn isEqualToString:@"call"] || [mn isEqualToString:@"bl"] || [mn isEqualToString:@"blr"]) {
        return [NSString stringWithFormat:@"call(%@);%@", i.operands.length ? i.operands : @"indirect", comment];
    }
    if ([mn isEqualToString:@"svc"] || [mn isEqualToString:@"syscall"] || [mn isEqualToString:@"int"]) {
        return [NSString stringWithFormat:@"system_call(%@);%@", i.operands.length ? i.operands : @"current_registers", comment];
    }
    if ([mn isEqualToString:@"xchg"] && ops.count >= 2) {
        return [NSString stringWithFormat:@"swap(%@, %@);%@", ops[0], ops[1], comment];
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
    return [NSString stringWithFormat:@"%@;%@", [self semanticFallbackForInstruction:i operands:ops], comment];
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
    NSString *m = [mnemonic.lowercaseString stringByReplacingOccurrencesOfString:@"." withString:@""];
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
    NSString *key = [mnemonic.lowercaseString stringByReplacingOccurrencesOfString:@"." withString:@""];
    return conditions[key] ?: [NSString stringWithFormat:@"condition_%@", key];
}

- (NSString *)conditionForConditionalMove:(NSString *)mnemonic {
    NSString *suffix = [mnemonic.lowercaseString stringByReplacingOccurrencesOfString:@"cmov" withString:@""];
    return [self conditionForConditionCode:suffix];
}

- (NSString *)conditionForSet:(NSString *)mnemonic {
    NSString *suffix = [mnemonic.lowercaseString stringByReplacingOccurrencesOfString:@"set" withString:@""];
    return [self conditionForConditionCode:suffix];
}

- (NSString *)conditionForConditionCode:(NSString *)code {
    NSDictionary<NSString *, NSString *> *conditions = @{
        @"e": @"flags.equal", @"z": @"flags.zero", @"ne": @"!flags.equal", @"nz": @"!flags.zero",
        @"g": @"flags.greater", @"ge": @"flags.greater_or_equal", @"l": @"flags.less", @"le": @"flags.less_or_equal",
        @"a": @"flags.above", @"ae": @"flags.above_or_equal", @"b": @"flags.below", @"be": @"flags.below_or_equal",
        @"o": @"flags.overflow", @"no": @"!flags.overflow", @"s": @"flags.sign", @"ns": @"!flags.sign",
        @"p": @"flags.parity", @"pe": @"flags.parity", @"np": @"!flags.parity", @"po": @"!flags.parity",
    };
    return conditions[code.lowercaseString] ?: [NSString stringWithFormat:@"condition_%@", code];
}

- (NSString *)semanticFallbackForInstruction:(DCInstruction *)instruction operands:(NSArray<NSString *> *)operands {
    NSString *name = [self sanitizedIdentifierFromString:instruction.mnemonic.lowercaseString prefix:@"op_"];
    if (operands.count == 0) {
        return [NSString stringWithFormat:@"%@_effect(state)", name];
    }
    return [NSString stringWithFormat:@"state = %@_effect(state, %@)", name, [operands componentsJoinedByString:@", "]];
}

- (NSString *)sanitizedIdentifierFromString:(NSString *)value prefix:(NSString *)prefix {
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"];
    NSMutableString *out = [NSMutableString stringWithString:prefix ?: @""];
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        [out appendFormat:@"%C", (unichar)([allowed characterIsMember:c] ? c : '_')];
    }
    return out;
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
