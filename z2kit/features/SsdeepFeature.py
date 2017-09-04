#    LstrfuzzyFeature
#    ELF ファイルの文字列テーブル (string table) を元にした特徴量
#    注: 昨日仮実装した Limpfuzzy (仮) を仮に改称

from .base.SsdeepBasedFeature import SsdeepBasedFeature

class SsdeepFeature(SsdeepBasedFeature):
    def __init__(self):
        pass
    def _construct_feature(self, elffile):
        self._update_data(elffile.data)
