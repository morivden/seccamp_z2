#    ELFDynamicData.py
#    Elf*_Dyn (ELF 動的リンク情報 [単独])

import struct
from z2kit.elf.ELFFileIdent import ELFFileIdent

#
#
#    定数リスト
#    (/usr/include/elf.h に簡易的だがもっと多彩な解説あり)
#
#

# d_tag
DT_NULL            = 0
DT_NEEDED          = 1   # 必要な共有ライブラリ等
DT_PLTRELSZ        = 2
DT_PLTGOT          = 3
DT_HASH            = 4
DT_STRTAB          = 5   # string table の位置
DT_SYMTAB          = 6
DT_RELA            = 7
DT_RELASZ          = 8
DT_RELAENT         = 9
DT_STRSZ           = 10  # string table のサイズ
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


#
#
#    ELF ファイルの動的リンク情報 (単独)
#
#

class ELFDynamicData:
    # ダミーの初期化
    def __init__(self, ident, data):
        self.d_tag = 0
        self.d_val = 0
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
            self.d_tag,
            self.d_val
        ) = struct.unpack(fmt, data)

# 32-bit 版の動的リンク情報 (Elf32_Dyn)
class ELFDynamicData32(ELFDynamicData):
    FORMAT = 'iI'
    LENGTH = 8
    def __init__(self, ident, data):
        ELFDynamicData.__init__(self, ident, data)
        self._read_data(ident, data)

# 64-bit 版の動的リンク情報 (Elf64_Dyn)
class ELFDynamicData64(ELFDynamicData):
    FORMAT = 'qQ'
    LENGTH = 16
    def __init__(self, ident, data):
        ELFDynamicData.__init__(self, ident, data)
        self._read_data(ident, data)
