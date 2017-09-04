#    HashBasedFeature
#    ハッシュを元とした特徴量 (基本クラス)
from .FeatureBase import FeatureBase

class HashBasedFeature(FeatureBase):
    def __init__(self):
        pass
    def _init_hash(self, input):
        pass
    def _update_data(self, data):
        pass
    def _get_final_hash(self, input):
        return None
    def _construct_feature(self, input):
        pass
    def get_feature(self, input):
        self._init_hash(input)
        self._construct_feature(input)
        return self._get_final_hash(input)
