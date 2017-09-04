#! /usr/bin/env python3
# stringsコマンドの結果を特徴量とする
# Usage: ./z2kit_find_strings_by_virustotal.py | ./histogram_to_graph.py /dev/stdin > TEXT
import glob
import json
import sys
import z2kit.elf
import z2kit.features

AV_SOFTWARE = 'Kaspersky'
EXPECTED_DETECTION = 'Virus.Linux.RST.b'

def set_features(elffile):
    if not isinstance(elffile, z2kit.elf.ELFFile):
        raise ValueError('ELFFile クラスを与えなければなりません。')
    elffile.features = {}
    elffile.features['md5']       = z2kit.features.MD5Feature().get_feature(elffile)
    #elffile.features['ssdeep']    = z2kit.features.SsdeepFeature().get_feature(elffile)
    #elffile.features['lstrfuzzy'] = z2kit.features.LstrfuzzyFeature().get_feature(elffile)
    elffile.features['strings']   = z2kit.features.StringsFeature().get_feature(elffile)

with open('virustotal-ELF-VXShare.json') as f:
    virustotal_info = json.load(f)

HISTOGRAM = {}
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
        strings = elffile.features['strings']
        for s in strings.keys():
            if s not in HISTOGRAM:
                HISTOGRAM[s] = 0
            HISTOGRAM[s] += strings[s]
    except:
        pass

json.dump(HISTOGRAM, sys.stdout)
