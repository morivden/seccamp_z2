#    ELFFileIdent.py
#    Elf*_Ehdr (ELF ヘッダーのうち、ELF ファイル識別用の情報)

#
#
#    定数リスト
#    (/usr/include/elf.h に簡易的な解説あり)
#
#

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

ELFMAG0 = 0x7f
ELFMAG1 = ord(b'E')
ELFMAG2 = ord(b'L')
ELFMAG3 = ord(b'F')

# e_ident[EI_CLASS]
ELFCLASS32   = 1
ELFCLASS64   = 2

# e_ident[EI_DATA]
ELFDATA2LSB  = 1
ELFDATA2MSB  = 2

# e_ident[EI_VERSION]
EV_CURRENT   = 1



#
#
#    ELF ファイル識別用情報
#
#

class ELFFileIdent:

    # ELF ファイルにはリトルエンディアンとビッグエンディアンの両方が有り得る。
    # Python で解析するために、エンディアンを struct.upack 用のプレフィックスに変換する。
    @classmethod
    def elf_data_to_unpack_endian(cls, data):
        if data == ELFDATA2LSB:
            return '<'
        if data == ELFDATA2MSB:
            return '>'
        raise ValueError()

    # 上記関数を、現在のデータに対して適用する
    def get_unpack_endian(self):
        return self.elf_data_to_unpack_endian(self.data[EI_DATA])

    # ELF ファイル識別用の情報を初期化する
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError('ELFFileIdent クラスの初期化には、バイト列が必要です。')
        if len(data) != EI_NIDENT:
            raise ValueError('ELFFileIdent クラスの初期化には、EI_NIDENT バイトの長さのバイト列が必要です。')
        self.data = bytes(data)
        if \
            self.data[EI_MAG0] != ELFMAG0 or \
            self.data[EI_MAG1] != ELFMAG1 or \
            self.data[EI_MAG2] != ELFMAG2 or \
            self.data[EI_MAG3] != ELFMAG3:
            raise ValueError('ELF ファイルエラー: ELF ファイルのマジックワードと一致しません。')
        if self.data[EI_VERSION] != EV_CURRENT:
            raise ValueError('ELF ファイルエラー: ELF ファイルのバージョンが有効なものではありません。')
