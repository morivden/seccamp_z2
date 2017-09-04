#    LstrfuzzyFeature
#    ELF ファイルの文字列テーブル (string table) を元にした特徴量
#    注: 昨日仮実装した Limpfuzzy (仮) を仮に改称

from .base.SsdeepBasedFeature import SsdeepBasedFeature

class LstrfuzzyFeature(SsdeepBasedFeature):
    def __init__(self):
        pass
    def _construct_feature(self, elffile):
        if not elffile.dynamic_info:
            return
        self._update_data(elffile.read_by_vaddr(
            elffile.dynamic_info.string_table_addr.d_val,
            elffile.dynamic_info.string_table_size.d_val
        ))
