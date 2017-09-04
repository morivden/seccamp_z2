#    ELFSectionHeader.py
#    Elf*_Shdr (ELF ヘッダーのうち、セクションヘッダー)

import struct
from z2kit.elf.ELFFileIdent import ELFFileIdent

#
#
#    定数リスト
#    (/usr/include/elf.h に簡易的だがもっと多彩な解説あり)
#
#

# sh_type
SHT_NULL          = 0
SHT_PROGBITS      = 1
SHT_SYMTAB        = 2
SHT_STRTAB        = 3
SHT_RELA          = 4
SHT_HASH          = 5
SHT_DYNAMIC       = 6
SHT_NOTE          = 7
SHT_NOBITS        = 8
SHT_REL           = 9
SHT_SHLIB         = 10
SHT_DYNSYM        = 11
SHT_INIT_ARRAY    = 14
SHT_FINI_ARRAY    = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP         = 17
SHT_SYMTAB_SHNDX  = 18
SHT_NUM           = 19


#
#
#    ELF ファイルのセクションヘッダー (基本クラス)
#
#

class ELFSectionHeader:
    # ダミーの初期化
    def __init__(self):
        self.sh_name      = 0
        self.sh_type      = 0
        self.sh_flags     = 0
        self.sh_addr      = 0
        self.sh_offset    = 0
        self.sh_size      = 0
        self.sh_link      = 0
        self.sh_info      = 0
        self.sh_addralign = 0
        self.sh_entsize   = 0
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
            self.sh_name,
            self.sh_type,
            self.sh_flags,
            self.sh_addr,
            self.sh_offset,
            self.sh_size,
            self.sh_link,
            self.sh_info,
            self.sh_addralign,
            self.sh_entsize
        ) = struct.unpack(fmt, data)

# 32-bit 版のセクションヘッダー (Elf32_Shdr)
class ELFSectionHeader32(ELFSectionHeader):
    FORMAT = 'IIIIIIIIII'
    LENGTH = 40
    def __init__(self, ident, data):
        ELFSectionHeader.__init__(self)
        self._read_data(ident, data)

# 64-bit 版のセクションヘッダー (Elf64_Shdr)
class ELFSectionHeader64(ELFSectionHeader):
    FORMAT = 'IIQQQQIIQQ'
    LENGTH = 64
    def __init__(self, ident, data):
        ELFSectionHeader.__init__(self)
        self._read_data(ident, data)
