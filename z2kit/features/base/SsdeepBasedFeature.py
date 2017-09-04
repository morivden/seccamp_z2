#    SsdeepBasedFeature
#    ハッシュを元とした特徴量 (基本クラス)

import ssdeep
from .HashBasedFeature import HashBasedFeature

class SsdeepBasedFeature(HashBasedFeature):
    def __init__(self):
        pass
    def _init_hash(self, input):
        self.hobj = ssdeep.Hash()
    def _update_data(self, data):
        self.hobj.update(data)
    def _get_final_hash(self, input):
        return self.hobj.digest(elimseq=True)
    def _construct_feature(self, input):
        pass
    def get_feature(self, input):
        self._init_hash(input)
        self._construct_feature(input)
        return self._get_final_hash(input)
