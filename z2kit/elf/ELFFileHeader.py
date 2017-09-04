#    ELFFileHeader.py
#    Elf*_Ehdr (ELF ファイルヘッダー) のうち識別用情報 (e_ident -> ELFFileIdent) 以外

import struct
from z2kit.elf.ELFFileIdent import ELFFileIdent

class ELFFileHeader:
    # ダミーの初期化
    def __init__(self, ident, data):
        self.e_type      = 0
        self.e_machine   = 0
        self.e_version   = 0
        self.e_entry     = 0
        self.e_phoff     = 0
        self.e_shoff     = 0
        self.e_flags     = 0
        self.e_ehsize    = 0
        self.e_phentsize = 0
        self.e_phnum     = 0
        self.e_shentsize = 0
        self.e_shnum     = 0
        self.e_shstrndx  = 0
    # データを読み取る
    def _read_data(self, ident, data):
        if not isinstance(ident, ELFFileIdent):
            raise ValueError('当オブジェクトの初期化には、ident に ELFFileIdent クラスのオブジェクトが必要です。')
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError('当オブジェクトの初期化には、data にバイト列が必要です。')
        if len(data) != type(self).LENGTH:
            raise ValueError('当オブジェクトの初期化に指定された data の長さが予期されたものではありません。指定した data に異常があるか、もしくが ELF ファイル内のエラーです。')
        fmt = ident.get_unpack_endian() + type(self).FORMAT
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
        ) = struct.unpack(fmt, data)

# 32-bit 版のファイルヘッダー (Elf32_Ehdr の e_ident 以外)
class ELFFileHeader32(ELFFileHeader):
    FORMAT = 'HHIIIIIHHHHHH'
    LENGTH = 36
    def __init__(self, ident, data):
        ELFFileHeader.__init__(self, ident, data)
        self._read_data(ident, data)

# 64-bit 版のファイルヘッダー (Elf64_Ehdr の e_ident 以外)
class ELFFileHeader64(ELFFileHeader):
    FORMAT = 'HHIQQQIHHHHHH'
    LENGTH = 48
    def __init__(self, ident, data):
        ELFFileHeader.__init__(self, ident, data)
        self._read_data(ident, data)
