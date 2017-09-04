#    ELFFile.py
#    ELF ファイル全体の情報
import io
from z2kit.elf.ELFFileIdent     import EI_NIDENT
from z2kit.elf.ELFFileIdent     import ELFFileIdent
from z2kit.elf.ELFFileClasses   import ELFFileClasses
from z2kit.elf.ELFProgramHeader import *
from z2kit.elf.ELFDynamicInfo   import ELFDynamicInfo

class ELFFile:
    # 指定されたファイル名のデータを読み取り、ELF ファイルとして初期化
    @classmethod
    def read_from_file(self, filename):
        with open(filename, 'rb') as f:
            data = f.read()
        return ELFFile(data)

    # ELF ファイルをバイト列から初期化
    def __init__(self, data):
        # データ構造の明示 (実際の初期化はこのメソッドの後の方で行う)
        self.data            = None  # ELF ファイルの内容
        self.ident           = None  # ELF 識別用情報
        self.file_header     = None  # ELF ファイルヘッダー
        self.program_headers = None  # ELF プログラムヘッダー (の配列)
        self.load_info       = None  # ELF プログラムヘッダーのうち、メモリにロードする指示 (の配列)
        self.interp_phdr     = None  # インタープリターのプログラムヘッダー (None の場合、存在しない)
        self.interp_info     = None  # インタープリターのパス (存在する場合; 正常な ELF ファイルでは NULL 終端文字列で、かつ必ず最後だけに NULL 文字を含むはず)
        self.dynamic_phdr    = None  # ELF 動的リンクのプログラムヘッダー (None の場合、存在しない)
        self.dynamic_info    = None  # ELF 動的リンク用情報
        # 引数のチェック
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError('ELFFile クラスの初期化には、ELF ファイル全体を示すバイト列が必要です。')
        self.data = bytes(data)
        # ELF ファイルヘッダーを読み取る
        with io.BytesIO(self.data) as fin:
            # 識別用データを読み取る
            fin = io.BytesIO(self.data)
            self.ident   = ELFFileIdent(fin.read(EI_NIDENT))
            self.classes = ELFFileClasses(self.ident)
            # 他のファイルヘッダーを読み取る
            cls = self.classes.ELFFileHeader
            self.file_header = cls(self.ident, fin.read(cls.LENGTH))
        # プログラムヘッダーを読み取る
        self.program_headers = []
        with io.BytesIO(self.data) as fin:
            if self.file_header.e_phnum != 0:
                fin.seek(self.file_header.e_phoff)
                for i in range(self.file_header.e_phnum):
                    cls = self.classes.ELFProgramHeaderBase
                    self.program_headers.append(cls(self.ident, fin.read(cls.LENGTH)))
        # プログラムヘッダーのうち、必要なものを抽出する
        self.load_info = [x for x in self.program_headers if x.p_type == PT_LOAD]
        self.interp_phdr = [x for x in self.program_headers if x.p_type == PT_INTERP]
        self.interp_phdr = self.interp_phdr[0] if len(self.interp_phdr) > 0 else None
        self.dynamic_phdr = [x for x in self.program_headers if x.p_type == PT_DYNAMIC]
        self.dynamic_phdr = self.dynamic_phdr[0] if len(self.dynamic_phdr) > 0 else None
        # インタープリターを取得する
        if self.interp_phdr:
            with io.BytesIO(self.data) as fin:
                fin.seek(self.interp_phdr.p_offset)
                self.interp_info = fin.read(self.interp_phdr.p_filesz)
        # 動的リンク情報を取得する
        if self.dynamic_phdr:
            cls = self.classes.ELFDynamicData
            with io.BytesIO(self.data) as fin:
                fin.seek(self.dynamic_phdr.p_offset)
                self.dynamic_info = ELFDynamicInfo(self.ident, cls, fin)

    # "仮想" アドレスで読み取る (読み取れない領域は 0 で埋める)
    def read_by_vaddr(self, vaddr, vsize):
        ary = bytearray(vsize)
        for load in self.load_info:
            range00 = load.p_vaddr - vaddr
            range01 = range00 + load.p_filesz
            range10 = 0
            range11 = load.p_filesz
            if range01 < 0:
                continue
            if range00 >= load.p_filesz:
                continue
            if range00 < 0:
                range10 -= range00
                range00 -= range00
            if range01 > vsize:
                overflow_size = range01 - vsize
                range11 -= overflow_size
                range01 -= overflow_size
            range10 += load.p_offset
            range11 += load.p_offset
            ary[range00:range01] = self.data[range10:range11]
        return bytes(ary)

    # "物理" アドレスで読み取る (読み取れない領域は 0 で埋める)
    def read_by_paddr(self, paddr, psize):
        ary = bytearray(psize)
        for load in self.load_info:
            range00 = load.p_paddr - paddr
            range01 = range00 + load.p_filesz
            range10 = 0
            range11 = load.p_filesz
            if range01 < 0:
                continue
            if range00 >= load.p_filesz:
                continue
            if range00 < 0:
                range10 -= range00
                range00 -= range00
            if range01 > psize:
                overflow_size = range01 - psize
                range11 -= overflow_size
                range01 -= overflow_size
            range10 += load.p_offset
            range11 += load.p_offset
            ary[range00:range01] = self.data[range10:range11]
        return bytes(ary)
