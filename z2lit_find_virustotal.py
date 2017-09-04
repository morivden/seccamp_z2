#! /usr/bin/env python3
# VirusTotalのメタデータから特定のアンチウィルスソフトウェアで特定の検出名を持つものを出力
# Usage: ./z2kit_find_virustotal.py
import glob
import json
import sys
import z2kit.elf
import z2kit.features

AV_SOFTWARE = 'Symantec'
EXPECTED_DETECTION = 'Linux.Backdoor.Kaiten'

def set_features(elffile):
    if not isinstance(elffile, z2kit.elf.ELFFile):
        raise ValueError('ELFFileクラスを与えなければなりません。')
    elffile.features = {}
    elffile.features['md5'] = z2kit.features.MD5Feature().get_feature(elffile)
    elffile.features['ssdeep'] = z2kit.features.SsdeepFeature().get_feature(elffile)
    elffile.features['lstrfuzzy'] = z2kit.features.LstrfuzzyFeature().get_feature(elffile)

with open('virustotal-ELF-VXShare.json') as f:
    virustotal_info = json.load(f)

for filename in glob.glob('z2/VirusShare_*'):
    try:
        elffile = z2kit.elf.ELFFile.read_from_file(filename)
        set_features(elffile)
        md5 = elffile.features['md5']
        if md5 not in virustotal_info:
            continue
        if AV_SOFTWARE not in virustotal_info[md5]['scans']:
            continue
        if not virustotal_info[md5]['scans'][AV_SOFTWARE]['detected']:
            continue
        if virustotal_info[md5]['scans'][AV_SOFTWARE]['result'] != EXPECTED_DETECTION:
            continue
        print(filename)
    except:
        raise
