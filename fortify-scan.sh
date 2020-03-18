#!/bin/bash

# Set scan options
# Modular scan doesn't work properly yet, so for now we just add the fortify-ssc-parser-util build model
# Note that either approach requires fortify-ssc-parser-util to be translated/scanned on the same machine
# before running this script.
#scanOpts="-include-modules fortify-ssc-parser-util -scan"
scanOpts="-b fortify-ssc-parser-util -scan" 

# Load and execute actual scan script from GitHub
curl -s https://raw.githubusercontent.com/fortify-ps/gradle-helpers/1.0/fortify-scan.sh | bash -s - ${scanOpts}
