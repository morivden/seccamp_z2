#    ELFDynamicInfo.py
#    ELF 動的リンク情報 (テーブル)

from z2kit.elf.ELFDynamicData import *

#
#
#    ELF ファイルの動的リンク情報 (テーブル)
#
#

class ELFDynamicInfo:
    # データを読み取る
    def __init__(self, ident, cls, stream):
        if not isinstance(ident, ELFFileIdent):
            raise ValueError('当オブジェクトの初期化には、ident に ELFFileIdent クラスのオブジェクトが必要です!')
        self.data = []
        while True:
            data = stream.read(cls.LENGTH)
            dyndata = cls(ident, data)
            self.data.append(dyndata)
            if dyndata.d_tag == DT_NULL:
                break
        # 必要な動的リンク情報が揃っているかどうかチェック
        mandatory_tags = [
            DT_NULL,
            DT_STRTAB,
            #DT_SYMTAB,
            DT_STRSZ,
            #DT_SYMENT,
        ]
        mandatory_infos = {}
        for dyn in self.data:
            mandatory_infos[dyn.d_tag] = dyn
        for tag in mandatory_tags:
            if tag not in mandatory_infos:
                raise ValueError('ELF ファイルエラー: 仕様上必須の情報が揃っていません。')
        # 必要な動的リンク情報に関わるタグを設定
        self.string_table_addr = mandatory_infos[DT_STRTAB]
        self.string_table_size = mandatory_infos[DT_STRSZ]
        #self.symbol_table_addr       = mandatory_infos[DT_SYMTAB]
        #self.symbol_table_entry_size = mandatory_infos[DT_SYMENT]
