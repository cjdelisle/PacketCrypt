#!/usr/bin/env python3
import math

# To see this script work, run `python3 ./docs/compression_recomputation.py`
# With 585ms time to compute a dataset and 512 announcement limit per dataset:
# Computation time ms/ann:   1.142578125
# Best compression ratio:    3.1604938271604937 : 1
# Recomputation time ms/ann: 0.17852783203125

# This is the number of milliseconds needed to compute a block of announcements.
DATASET_COMPUTE_TIME=585

# This is the size limit for a block of announcements.
ANN_LIM=512

print("""
The best known technique for compressing a block of announcements is to remove duplicate
data in the merkle proofs. The savings from this technique depends on the number of
announcements which can be generated in one block (from one dataset).

Recomputation is needed for announcement validation, but mass validation of a block of
announcements can double as decompression.
""")

print("Computation time ms/ann:   " + str(DATASET_COMPUTE_TIME/ANN_LIM))
print("Best compression ratio:    " + str(
    1 / ((
        ANN_LIM * 64 + # layer of the merkle from which all above layers can be computed
        ANN_LIM * int(math.log2(8192/ANN_LIM))*64 + # proofs back from the end to that layer
        ANN_LIM * 4 # some kind of a seed (assume 4 bytes)
    ) / (
        ANN_LIM * 1024 # honest announcements
    ))
) + " : 1")
print("Recomputation time ms/ann: " + str(
    DATASET_COMPUTE_TIME * ((
        # need to re-compute 4 elements, but never more than 8192 (the total tree)
        min(ANN_LIM*4, 8192) +
        # need to re-compute the 5th element as well
        ANN_LIM
    ) / 16384) / ANN_LIM
))
