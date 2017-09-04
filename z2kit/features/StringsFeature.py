#    ELFStringsFeature
#    特徴量 (基本クラス)

from .base.FeatureBase import FeatureBase

class StringsFeature(FeatureBase):
    def __init__(self):
        self.minlen = 4
    def get_feature(self, elffile):
        histogram = {}
        bs = bytearray(b'')
        for b in elffile.data:
            if b >= 0x20 and b < 0x7f:
                bs.append(b)
            else:
                if len(bs) >= self.minlen:
                    s = bs.decode('ASCII')
                    if s not in histogram:
                        histogram[s] = 0
                    histogram[s] += 1
                    bs = bytearray(b'')
        if len(bs) >= self.minlen:
            s = bs.decode('ASCII')
            if s not in histogram:
                histogram[s] = 0
            histogram[s] += 1
        return histogram
