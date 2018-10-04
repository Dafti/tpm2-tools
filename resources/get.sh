#!/bin/bash

echo "ibmtpm"
curl -L https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm1332.tar.gz --output ibmtpm1332.tar.gz
echo "tpm2-tss"
curl -L https://github.com/intel/tpm2-tss/archive/master.zip --output tpm2-tss.zip
echo "tpm2-abrmd"
curl -L https://github.com/intel/tpm2-abrmd/archive/master.zip --output tpm2-abrmd.zip
echo "tpm2-tools"
curl -L https://github.com/intel/tpm2-tools/archive/master.zip --output tpm2-tools.zip
