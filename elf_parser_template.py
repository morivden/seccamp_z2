#! /usr/bin/env python3
import json
import re
import struct
import ssdeep
import sys

#
#
#    ELF ファイルヘッダ関連 (Elf32_Ehdr / Elf64_Ehdr)
#
#
UPACK_EHEADER_1    = '=16B'
UPACK_EHEADER_2_32 = 'HHIIIIIHHHHHH'
UPACK_EHEADER_2_64 = 'HHIQQQIHHHHHH'
LEN_EHEADER_2_32   = 36
LEN_EHEADER_2_64   = 48

EI_MAG0       = 0
EI_MAG1       = 1
EI_MAG2       = 2
EI_MAG3       = 3
EI_CLASS      = 4
EI_DATA       = 5
EI_VERSION    = 6
EI_OSABI      = 7
EI_ABIVERSION = 8
EI_PAD        = 9
EI_NIDENT     = 16

# eident[EI_CLASS]
ELFCLASS32   = 1
ELFCLASS64   = 2

# eident[EI_DATA]
ELFDATA2LSB  = 1
ELFDATA2MSB  = 2

# eident[EI_VERSION]
EV_CURRENT   = 1


#
#
#    ELF ダイナミック情報 (Elf32_Dyn / Elf64_Dyn)
#
#
UPACK_DYN_32 = 'iI'
UPACK_DYN_64 = 'qQ'
LEN_DYN_32 = 8
LEN_DYN_64 = 16

DT_NULL            = 0
DT_NEEDED          = 1
DT_PLTRELSZ        = 2
DT_PLTGOT          = 3
DT_HASH            = 4
DT_STRTAB          = 5
DT_SYMTAB          = 6
DT_RELA            = 7
DT_RELASZ          = 8
DT_RELAENT         = 9
DT_STRSZ           = 10
DT_SYMENT          = 11
DT_INIT            = 12
DT_FINI            = 13
DT_SONAME          = 14
DT_RPATH           = 15
DT_SYMBOLIC        = 16
DT_REL             = 17
DT_RELSZ           = 18
DT_RELENT          = 19
DT_PLTREL          = 20
DT_DEBUG           = 21
DT_TEXTREL         = 22
DT_JMPREL          = 23
DT_BIND_NOW        = 24
DT_INIT_ARRAY      = 25
DT_FINI_ARRAY      = 26
DT_INIT_ARRAYSZ    = 27
DT_FINI_ARRAYSZ    = 28
DT_RUNPATH         = 29
DT_FLAGS           = 30
DT_ENCODING        = 32
DT_PREINIT_ARRAY   = 32
DT_PREINIT_ARRAYSZ = 33

class ELFDynamic:
    def __init__(self):
        self.d_tag = 0
        self.d_val = 0

#
#
#    ELF プログラムヘッダ関連 (Elf32_Phdr / Elf64_Phdr)
#
#
UPACK_PHEADER_32 = 'IIIIIIII'
UPACK_PHEADER_64 = 'IIQQQQQQ'
LEN_PHEADER_32   = 32
LEN_PHEADER_64   = 56

# p_type
PT_NULL         = 0
PT_LOAD         = 1
PT_DYNAMIC      = 2
PT_INTERP       = 3
PT_NOTE         = 4
PT_SHLIB        = 5
PT_PHDR         = 6
PT_TLS          = 7
PT_NUM          = 8
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_EH_STACK = 0x6474e551
PT_GNU_EH_RELRO = 0x6474e552

# p_flags
PF_X  = 1
PF_W  = 2
PF_R  = 4

class ELFProgramHeader:
    def __init__(self):
        self.p_type   = 0
        self.p_offset = 0
        self.p_vaddr  = 0
        self.p_paddr  = 0
        self.p_filesz = 0
        self.p_memsz  = 0
        self.p_flags  = 0
        self.p_align  = 0

# 32-bit の ELF プログラムヘッダ
class ELFProgramHeader32(ELFProgramHeader):
    def __init__(self, f, eident):
        ELFProgramHeader.__init__(self)
        endian_prefix = ELFFile.elf_data_to_unpack_endian(eident[EI_DATA])
        phdr_len = LEN_PHEADER_32
        phdr_fmt = endian_prefix + UPACK_PHEADER_32
        (
            self.p_type,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_flags,
            self.p_align
        ) = struct.unpack(phdr_fmt, f.read(phdr_len))

# 64-bit の ELF プログラムヘッダ
class ELFProgramHeader64(ELFProgramHeader):
    def __init__(self, f, eident):
        ELFProgramHeader.__init__(self)
        endian_prefix = ELFFile.elf_data_to_unpack_endian(eident[EI_DATA])
        phdr_len = LEN_PHEADER_64
        phdr_fmt = endian_prefix + UPACK_PHEADER_64
        (
            self.p_type,
            self.p_flags,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_align
        ) = struct.unpack(phdr_fmt, f.read(phdr_len))

#
#
#    ELF ファイル
#
#
class ELFFile:

    # ELF ファイルにはリトルエンディアンとビッグエンディアンの両方が有り得る。
    # Python で解析するために、エンディアンを struct.upack 用のプレフィックスに変換する。
    @classmethod
    def elf_data_to_unpack_endian(cls, data):
        if data == ELFDATA2LSB:
            return '<'
        if data == ELFDATA2MSB:
            return '>'
        raise ValueError()

    # 動的リンク情報をひとつ分読み取る
    def read_dynamic_one(self):
        dyn = ELFDynamic()
        (
            dyn.d_tag,
            dyn.d_val
        ) = struct.unpack(self.edyn_fmt, self.fd.read(self.edyn_len))
        return dyn

    def __init__(self, filename):
        # ファイルをバイナリモードで開く
        self.fd = open(filename, 'rb')
        # ELF の先頭 EI_NIDENT (16) バイトに後のヘッダをどう読み取るべきか
        # 必要な情報が含まれている
        self.eident = struct.unpack(UPACK_EHEADER_1, self.fd.read(EI_NIDENT))
        # ELF ファイルのチェック
        if \
            self.eident[EI_MAG0] != 0x7f or \
            self.eident[EI_MAG1] != ord(b'E') or \
            self.eident[EI_MAG2] != ord(b'L') or \
            self.eident[EI_MAG3] != ord(b'F'):
            raise ValueError()
        if self.eident[EI_VERSION] != EV_CURRENT:
            raise ValueError()
        # エンディアンを決定
        endian_prefix = ELFFile.elf_data_to_unpack_endian(self.eident[EI_DATA])
        # 32-bit / 64-bit それぞれでの読み方を決める
        ehdr_fmt = endian_prefix
        self.edyn_fmt = endian_prefix
        if   self.eident[EI_CLASS] == ELFCLASS32:
            ehdr_len   = LEN_EHEADER_2_32
            ehdr_fmt  += UPACK_EHEADER_2_32
            phdr_class = ELFProgramHeader32
            self.edyn_len   = LEN_DYN_32
            self.edyn_fmt  += UPACK_DYN_32
        elif self.eident[EI_CLASS] == ELFCLASS64:
            ehdr_len  = LEN_EHEADER_2_64
            ehdr_fmt += UPACK_EHEADER_2_64
            phdr_class = ELFProgramHeader64
            self.edyn_len   = LEN_DYN_64
            self.edyn_fmt  += UPACK_DYN_64
        else:
            raise ValueError()
        # ELF ヘッダの残りを読み取る
        (
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx
        ) = struct.unpack(ehdr_fmt, self.fd.read(ehdr_len))
        # プログラムヘッダを読み取る
        self.phdrs = []
        if self.e_phnum != 0:
            self.fd.seek(self.e_phoff)
        for i in range(self.e_phnum):
            phdr = phdr_class(self.fd, self.eident)
            self.phdrs.append(phdr)
        # 動的リンク情報を読み取る
        for i in range(len(self.phdrs)):
            phdr = self.phdrs[i]
            if phdr.p_type == PT_DYNAMIC:
                self.fd.seek(phdr.p_offset)
                ndyn = phdr.p_filesz // self.edyn_len
                phdr.dyns = []
                for j in range(ndyn):
                    phdr.dyns.append(self.read_dynamic_one())
    # "物理" アドレスで読み取る (読み取れない領域は 0 で埋める)
    def read_by_paddr(self, paddr, psize):
        ary = bytearray(psize)
        range0 = 0
        range1 = psize
        for phdr in self.phdrs:
            if phdr.p_type == PT_LOAD:
                self.fd.seek(phdr.p_offset)
                data = self.fd.read(phdr.p_filesz)
                for i in range(len(data)):
                    o = phdr.p_paddr + i - paddr
                    if o < 0:
                        continue
                    if o >= psize:
                        continue
                    ary[o] = data[i]
        return bytes(ary)


#
#
#    ELF 特徴量抽出
#
#
class ELFFeature:
    def __init__(self, elffile):
        self.elffile = elffile
    def construct_feature(self):
        pass
    def get_feature(self):
        return None

class ELFHashFeature(ELFFeature):
    def __init__(self, elffile):
        ELFFeature.__init__(self, elffile)
    def update_data(self, data):
        pass

class ELFSsdeepFeature(ELFHashFeature):
    def __init__(self, elffile):
        ELFHashFeature.__init__(self, elffile)
        self.hobj = ssdeep.Hash()
    def update_data(self, data):
        self.hobj.update(data)
    def get_feature(self):
        return self.hobj.digest(elimseq=True)

class ELFStringsFeature(ELFFeature):
    def __init__(self, elffile):
        ELFFeature.__init__(self, elffile)
        self.minlen = 4
    def construct_feature(self):
        self.feature = {}
        self.elffile.fd.seek(0)
        bs = bytearray(b'')
        while True:
            data = self.elffile.fd.read(4096)
            if not data:
                break
            for b in data:
                if b >= 0x20 and b < 0x7f:
                    bs.append(b)
                else:
                    if len(bs) >= self.minlen:
                        s = bs.decode('ASCII')
                        if s not in self.feature:
                            self.feature[s] = 0
                        self.feature[s] += 1
                        bs = bytearray(b'')
        if len(bs) >= self.minlen:
            s = bs.decode('ASCII')
            if s not in self.feature:
                self.feature[s] = 0
            self.feature[s] += 1
    def get_feature(self):
        return self.feature

#
#
#    プログラムを書く
#
#

# impfuzzy のように ELF ファイルの必要な部分を読めるか? : Linux + impfuzzy = Limpfuzzy (仮)
class LimpfuzzyFeature(ELFSsdeepFeature):
    def __init__(self, elffile):
        ELFSsdeepFeature.__init__(self, elffile)
    def construct_feature(self):
        elffile = self.elffile
        for phdr in elffile.phdrs:
            if phdr.p_type == PT_DYNAMIC:
                # 動的リンク情報を読み取る
                strtab_offset = None
                strtab_length = None
                ### 課題:
                ### strtab_offset と strtab_length を、DYNAMIC 情報 (phdr.dyns 配列) から構築しよう
                for dyn in phdr.dyns:
                    if dyn.d_tag == DT_STRTAB:
                        strtab_offset = dyn.d_val
                    if dyn.d_tag == DT_STRSZ:
                        strtab_length = dyn.d_val
                data = elffile.read_by_paddr(strtab_offset, strtab_length)
                self.update_data(data)

### 課題:
### インターフェースを改良して、色々なファイルの情報が得られるようにしよう
for filename in sys.argv[1:]:
    try:
        elffile = ELFFile(filename)
        feature = LimpfuzzyFeature(elffile)
        feature.construct_feature()
        print(filename, feature.get_feature())
    except:
        pass
