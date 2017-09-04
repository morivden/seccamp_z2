#    MD5Feature
#    特徴量? : MD5

import hashlib

from .base.HashBasedFeature import HashBasedFeature

class MD5Feature(HashBasedFeature):
    def __init__(self):
        pass
    def _init_hash(self, input):
        self.hobj = hashlib.md5()
    def _update_data(self, data):
        self.hobj.update(data)
    def _get_final_hash(self, input):
        return self.hobj.hexdigest()
    def _construct_feature(self, elffile):
        self._update_data(elffile.data)
