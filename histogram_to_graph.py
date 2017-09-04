#! /usr/bin/env python3
# JSONファイルをもとにヒストグラムを作成
# Usage: ./histogram_to_graph.py JSON_FILE
import json
import sys

WIDTH = 40
FILLER = '#'
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    obj = json.load(f)
m = 0
for v in obj.values():
    m = max(v, m)
FORMAT = '{}{} {:' + str(len(str(m))) + 'd} {}'
for i, v in sorted(obj.items(), key=lambda x:-x[1]):
    g = int((WIDTH - 1) * 1.0 * v / m)
    g = FILLER * g + ' ' * (WIDTH - 1 - g)
    print(FORMAT.format(FILLER, g, v, i))
