#    ELFProgramHeader.py
#    Elf*_Phdr (ELF ヘッダーのうち、プログラムヘッダー)

import struct
from z2kit.elf.ELFFileIdent import ELFFileIdent

#
#
#    定数リスト
#    (/usr/include/elf.h に簡易的だがもっと多彩な解説あり)
#
#

# p_type (プログラムヘッダーの種別)
PT_NULL         = 0
PT_LOAD         = 1   # ファイルの内容をメモリに展開する指示
PT_DYNAMIC      = 2   # 動的リンクのために必要な情報各種
PT_INTERP       = 3   # 動的リンクを実際に行うインタープリターの名前
PT_NOTE         = 4
PT_SHLIB        = 5
PT_PHDR         = 6
PT_TLS          = 7
PT_NUM          = 8
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_EH_STACK = 0x6474e551
PT_GNU_EH_RELRO = 0x6474e552

# p_flags (プログラムヘッダーの属性)
PF_X  = 1   # 実行可能
PF_W  = 2   # 書き込み可能
PF_R  = 4   # 読み取り可能


#
#
#    ELF ファイルのプログラムヘッダー (基本クラス)
#
#

class ELFProgramHeaderBase:
    def __init__(self):
        self.p_type   = 0
        self.p_offset = 0
        self.p_vaddr  = 0
        self.p_paddr  = 0
        self.p_filesz = 0
        self.p_memsz  = 0
        self.p_flags  = 0
        self.p_align  = 0

# 32-bit 版のプログラムヘッダー (Elf32_Phdr)
class ELFProgramHeaderBase32(ELFProgramHeaderBase):
    FORMAT = 'IIIIIIII'
    LENGTH = 32
    def __init__(self, ident, data):
        ELFProgramHeaderBase.__init__(self)
        if not isinstance(ident, ELFFileIdent):
            raise ValueError('当オブジェクトの初期化には、ident に ELFFileIdent クラスのオブジェクトが必要です。')
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError('当オブジェクトの初期化には、data にバイト列が必要です。')
        if len(data) != self.LENGTH:
            raise ValueError('当オブジェクトの初期化に指定された data の長さが予期されたものではありません。指定した data に異常があるか、もしくが ELF ファイル内のエラーです。')
        fmt = ident.get_unpack_endian() + self.FORMAT
        (
            self.p_type,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_flags,
            self.p_align
        ) = struct.unpack(fmt, data)

# 64-bit 版のプログラムヘッダー (Elf64_Phdr)
class ELFProgramHeaderBase64(ELFProgramHeaderBase):
    FORMAT = 'IIQQQQQQ'
    LENGTH = 56
    def __init__(self, ident, data):
        ELFProgramHeaderBase.__init__(self)
        if not isinstance(ident, ELFFileIdent):
            raise ValueError('当オブジェクトの初期化には、ident に ELFFileIdent クラスのオブジェクトが必要です。')
        if type(data) != bytes and type(data) != bytearray:
            raise ValueError('当オブジェクトの初期化には、data にバイト列が必要です。')
        if len(data) != self.LENGTH:
            raise ValueError('当オブジェクトの初期化に指定された data の長さが予期されたものではありません。指定した data に異常があるか、もしくが ELF ファイル内のエラーです。')
        fmt = ident.get_unpack_endian() + self.FORMAT
        (
            self.p_type,
            self.p_flags,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_align
        ) = struct.unpack(fmt, data)
