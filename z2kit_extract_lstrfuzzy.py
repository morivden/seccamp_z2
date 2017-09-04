#! /usr/bin/env python3
# ファイルリストを受け取ってlstrfuzzyデータを出力
# Usage: ./z2kit_extract_lstrfuzzy.py FILELIST
import sys
import z2kit.elf
import z2kit.features

def set_features(elffile):
    if not isinstance(elffile, z2kit.elf.ELFFile):
        raise ValueError('ELFファイルを与えなければなりません。')
    elffile.features = {}
    elffile.features['md5'] = z2kit.features.MD5Feature().get_feature(elffile)
    elffile.features['ssdeep'] = z2kit.features.SsdeepFeature().get_feature(elffile)
    elffile.features['lstrfuzzy'] = z2kit.features.LstrfuzzyFeature().get_feature(elffile)

with open(sys.argv[1], 'r') as f:
    for ln in f:
        filename = ln[:-1]
        try:
            elffile = z2kit.elf.ELFFile.read_from_file(filename)
            set_features(elffile)
            print(filename, elffile.features['lstrfuzzy'])
        except:
            pass
