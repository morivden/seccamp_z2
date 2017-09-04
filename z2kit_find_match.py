#! /usr/bin/env python3
# z2kit_extract_lstrfuzzy.pyの結果をもとに検出器を作成する
# 検出器を使った結果とz2kit_find_virustotal.pyとの結果を比較する
# Usage: ./z2_find_match.py
import glob
import json
import sys
import z2kit.elf
import z2kit.features
import ssdeep

AV_SOFTWARE = 'Symantec'
EXPECTED_DETECTION = 'Linux.Backdoor.Kaiten'

def set_features(elffile):
    if not isinstance(elffile, z2kit.elf.ELFFile):
        raise ValueError('ELFFile クラスを与えなければなりません。')
    elffile.features = {}
    elffile.features['md5']       = z2kit.features.MD5Feature().get_feature(elffile)
    elffile.features['ssdeep']    = z2kit.features.SsdeepFeature().get_feature(elffile)
    elffile.features['lstrfuzzy'] = z2kit.features.LstrfuzzyFeature().get_feature(elffile)

def is_malware_to_focus(elffile):
    return \
        ssdeep.compare(elffile.features['lstrfuzzy'], '12:TKLJUWLLSQzisKFl1oXNt87U9fPG9K1pSzMT:WfzirnYVPG7gT') >= 50 or \
        ssdeep.compare(elffile.features['lstrfuzzy'], '12:lQn5o+ZirjsgAk3MRW7ll8+XS+wPKs0fI:OndZirjbp5l3Ex0fI') >= 50 or \
        ssdeep.compare(elffile.features['lstrfuzzy'], '12:GXkVn5o+ZirjsgAk3MRW7ll8+XS+wPKs04:GXAndZirjbp5l3Ex04') >= 50

for filename in glob.glob('z2/VirusShare_*'):
    try:
        elffile = z2kit.elf.ELFFile.read_from_file(filename)
        set_features(elffile)
        if is_malware_to_focus(elffile):
            print(filename)
    except:
        pass
