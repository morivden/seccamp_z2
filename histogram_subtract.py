#! /usr/bin/env python3
# 左側の内容から右側の内容を引いたJSONファイルを生成
# マルウェアから抽出した文字列からbinやlibに含まれる問題のない文字列を取り除く
# Usage: ./histogram_subtract.py JSON_FILE JSON_FILE > JSON_FILE_SUBTRACTED
import json
import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    obj1 = json.load(f)
with open(sys.argv[2], 'r', encoding='utf-8') as f:
    obj2 = json.load(f)
for i in obj2.keys():
    if i in obj1:
        del obj1[i]
json.dump(obj1, sys.stdout)
