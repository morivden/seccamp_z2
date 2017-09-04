#! /usr/bin/env python3
# ファイルを投げて比較
# Usage: ./file_ssdeep_compare.py FILE1 FILE2
import ssdeep
import sys
print(ssdeep.compare(ssdeep.hash_from_file(sys.argv[1]), ssdeep.hash_from_file(sys.argv[2])))
