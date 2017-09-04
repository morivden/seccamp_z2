#    ELFFileClasses.py
#    32-bit / 64-bit の ELF ファイルを動的に読み取るためのクラススイッチ

from z2kit.elf.ELFFileIdent     import EI_CLASS, ELFCLASS32, ELFCLASS64
from z2kit.elf.ELFFileIdent     import ELFFileIdent
from z2kit.elf.ELFFileHeader    import ELFFileHeader32, ELFFileHeader64
from z2kit.elf.ELFProgramHeader import ELFProgramHeaderBase32, ELFProgramHeaderBase64
from z2kit.elf.ELFDynamicData   import ELFDynamicData32, ELFDynamicData64

class ELFFileClasses:
    def __init__(self, ident):
        if not isinstance(ident, ELFFileIdent):
            raise ValueError('ELFFileClasses オブジェクトの初期化には、ELFFileIdent クラスのオブジェクトが必要です。')
        cls = ident.data[EI_CLASS]
        if   cls == ELFCLASS32:
            self.ELFFileHeader        = ELFFileHeader32
            self.ELFProgramHeaderBase = ELFProgramHeaderBase32
            self.ELFDynamicData       = ELFDynamicData32
        elif cls == ELFCLASS64:
            self.ELFFileHeader        = ELFFileHeader64
            self.ELFProgramHeaderBase = ELFProgramHeaderBase64
            self.ELFDynamicData       = ELFDynamicData64
        else:
            raise ValueError('ELF ファイルエラー: 32-bit と 64-bit の ELF ファイル "クラス" のみをサポートしています。')
