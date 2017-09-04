#! /usr/bin/env python3
# stringsコマンドの特徴量をもとにz2kit_find_strings_by_virustotal.pyとの結果を比較
# Usage: ./z2kit_find_strings_match.py
import glob
import json
import sys
import z2kit.elf
import z2kit.features
import ssdeep

def set_features(elffile):
    if not isinstance(elffile, z2kit.elf.ELFFile):
        raise ValueError('ELFFile クラスを与えなければなりません。')
    elffile.features = {}
    #elffile.features['md5']       = z2kit.features.MD5Feature().get_feature(elffile)
    #elffile.features['ssdeep']    = z2kit.features.SsdeepFeature().get_feature(elffile)
    elffile.features['lstrfuzzy'] = z2kit.features.LstrfuzzyFeature().get_feature(elffile)
    elffile.features['strings']   = z2kit.features.StringsFeature().get_feature(elffile)

def is_strings_matching(elffile, substring):
    for k in elffile.features['strings'].keys():
        if substring in k:
            return True
    return False

def is_malware_to_focus(elffile):
    return is_strings_matching(elffile, '********************')

for filename in glob.glob('z2/VirusShare_*'):
    try:
        elffile = z2kit.elf.ELFFile.read_from_file(filename)
        set_features(elffile)
        if is_malware_to_focus(elffile):
            print(filename)
    except:
        pass
