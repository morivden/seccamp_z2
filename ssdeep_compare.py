#! /usr/bin/env python3
# Usage: ./ssdeep_compare.py HASH1 HASH2
import ssdeep
import sys
print(ssdeep.compare(sys.argv[1], sys.argv[2]))
