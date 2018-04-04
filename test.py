#!/bin/env python

from certify_config import *

f = open("test.out", "w")
f.write("clamscan_list = " + str(clamscan_list))
f.close()
