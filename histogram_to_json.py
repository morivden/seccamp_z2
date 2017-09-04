#! /usr/bin/env python3
# binとlibのstringsコマンドの結果をヒストグラムにする
# { find /usr/bin/ /usr/sbin/ -type f -print0 ; find /lib/ /lib64/ /usr/lib/ -type f \( -name '*.so' -o -name '*.so.*' \) -print0 ; }
# | xargs -0 strings -a | sort | uniq -c | sort -s -n -k 1 > bins_and_libs.txt
# Usage: ./histogram_to_json.py TEXT > JSON_FILE
import json
import re
import sys

PAT_HISTOGRAM = re.compile('[ ]*([0-9]+) (.*)')
histogram = {}

with open(sys.argv[1], 'r') as f:
    for ln in f:
        l = ln[:-1]
        m = PAT_HISTOGRAM.fullmatch(l)
        if not m:
            raise ValueError()
        histogram[m.group(2)] = int(m.group(1), 10)

json.dump(histogram, sys.stdout)
