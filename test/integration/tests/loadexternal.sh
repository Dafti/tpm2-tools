#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

source helpers.sh

alg_primary_obj=sha256
alg_primary_key=rsa
alg_create_obj=sha256
alg_create_key=hmac

file_primary_key_ctx=context.p_"$alg_primary_obj"_"$alg_primary_key"
file_loadexternal_key_pub=opu_"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_priv=opr_"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_name=name.loadexternal_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_loadexternal_key_ctx=ctx_loadexternal_out_"$alg_primary_obj"_"$alg_primary_key"-"$alg_create_obj"_"$alg_create_key"
file_loadexternal_output=loadexternal_"$file_loadexternal_key_ctx"

Handle_parent=0x81010019

cleanup() {
  rm -f $file_primary_key_ctx $file_loadexternal_key_pub $file_loadexternal_key_priv \
    $file_loadexternal_key_name $file_loadexternal_key_ctx \
    $file_loadexternal_output private.pem public.pem plain.txt \
    plain.rsa.dec key.ctx public.ecc.pem private.ecc.pem \
    data.in.digest data.out.signed ticket.out name.bin stdout.yaml

  ina "$@" "keep_handle"
  if [ $? -ne 0 ]; then
    tpm2_evictcontrol -Q -ao -c $Handle_parent 2>/dev/null || true
  fi

  ina "$@" "no-shut-down"
  if [ $? -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear

run_tss_test() {
  printf "################################################################################\n"
  printf "# run_tss_test START\n"

  printf "> tpm2_createprimary -Q -a e -g $alg_primary_obj -G $alg_primary_key -o $file_primary_key_ctx\n"
  tpm2_createprimary -Q -a e -g $alg_primary_obj -G $alg_primary_key -o $file_primary_key_ctx

  printf "> tpm2_create -Q -g $alg_create_obj -G $alg_create_key -u $file_loadexternal_key_pub -r $file_loadexternal_key_priv  -C $file_primary_key_ctx\n"
  tpm2_create -Q -g $alg_create_obj -G $alg_create_key -u $file_loadexternal_key_pub -r $file_loadexternal_key_priv  -C $file_primary_key_ctx

  printf "> tpm2_loadexternal -Q -a n   -u $file_loadexternal_key_pub   -o $file_loadexternal_key_ctx\n"
  tpm2_loadexternal -Q -a n   -u $file_loadexternal_key_pub   -o $file_loadexternal_key_ctx

  printf "> tpm2_evictcontrol -Q -a o -c $file_primary_key_ctx -p $Handle_parent\n"
  tpm2_evictcontrol -Q -a o -c $file_primary_key_ctx -p $Handle_parent

  # Test with Handle
  printf "> cleanup \"keep_handle\" \"no-shut-down\"\n"
  cleanup "keep_handle" "no-shut-down"

  printf "> tpm2_create -Q -C $Handle_parent   -g $alg_create_obj  -G $alg_create_key -u $file_loadexternal_key_pub  -r  $file_loadexternal_key_priv\n"
  tpm2_create -Q -C $Handle_parent   -g $alg_create_obj  -G $alg_create_key -u $file_loadexternal_key_pub  -r  $file_loadexternal_key_priv

  printf "> tpm2_loadexternal -Q -a n   -u $file_loadexternal_key_pub\n"
  tpm2_loadexternal -Q -a n   -u $file_loadexternal_key_pub

  # Test with default hierarchy (and handle)
  printf "> cleanup \"keep_handle\" \"no-shut-down\"\n"
  cleanup "keep_handle" "no-shut-down"

  printf "> tpm2_create -Q -C $Handle_parent -g $alg_create_obj -G $alg_create_key -u $file_loadexternal_key_pub -r  $file_loadexternal_key_priv\n"
  tpm2_create -Q -C $Handle_parent -g $alg_create_obj -G $alg_create_key -u $file_loadexternal_key_pub -r  $file_loadexternal_key_priv

  printf "> tpm2_loadexternal -Q -u $file_loadexternal_key_pub\n"
  tpm2_loadexternal -Q -u $file_loadexternal_key_pub

  printf "# run_tss_test END\n"
  printf "################################################################################\n"
}

# Test loading an OSSL generated private key with a password
run_rsa_test() {
  printf "################################################################################\n"
  printf "# run_rsa_test START\n"

  printf "> openssl genrsa -out private.pem $1\n"
  openssl genrsa -out private.pem $1
  printf "> openssl rsa -in private.pem -out public.pem -outform PEM -pubout\n"
  openssl rsa -in private.pem -out public.pem -outform PEM -pubout

  printf "> echo \"hello world\" > plain.txt\n"
  echo "hello world" > plain.txt
  printf "> openssl rsautl -encrypt -inkey public.pem -pubin -in plain.txt -out plain.rsa.enc\n"
  openssl rsautl -encrypt -inkey public.pem -pubin -in plain.txt -out plain.rsa.enc

  printf "> tpm2_loadexternal -G rsa -a n -p foo -r private.pem -o key.ctx\n"
  tpm2_loadexternal -G rsa -a n -p foo -r private.pem -o key.ctx

  printf "> tpm2_rsadecrypt -c key.ctx -p foo -I plain.rsa.enc -o plain.rsa.dec\n"
  tpm2_rsadecrypt -c key.ctx -p foo -I plain.rsa.enc -o plain.rsa.dec

  printf "> diff plain.txt plain.rsa.dec\n"
  diff plain.txt plain.rsa.dec

  # try encrypting with the public key and decrypting with the private
  printf "> tpm2_loadexternal -G rsa -a n -p foo -u public.pem -o key.ctx\n"
  tpm2_loadexternal -G rsa -a n -p foo -u public.pem -o key.ctx

  # printf "> tpm2_rsaencrypt -Tmssim -c key.ctx plain.txt -o plain.rsa.enc\n"
  # tpm2_rsaencrypt -Tmssim -c key.ctx plain.txt -o plain.rsa.enc
  printf "> tpm2_rsaencrypt -T${TPM2TOOLS_TCTI} -c key.ctx plain.txt -o plain.rsa.enc\n"
  tpm2_rsaencrypt -T${TPM2TOOLS_TCTI} -c key.ctx plain.txt -o plain.rsa.enc

  printf "> openssl rsautl -decrypt -inkey private.pem -in plain.rsa.enc -out plain.rsa.dec\n"
  openssl rsautl -decrypt -inkey private.pem -in plain.rsa.enc -out plain.rsa.dec

  printf "> diff plain.txt plain.rsa.dec\n"
  diff plain.txt plain.rsa.dec

  printf "# run_rsa_test END\n"
  printf "################################################################################\n"
}

#
# Verify loading an external AES key.
#
# Paramter 1: The AES keysize to create in bytes.
#
# Notes: Also tests that name output and YAML output are valid.
#
run_aes_test() {
  printf "################################################################################\n"
  printf "# run_aes_test START\n"

  printf "> dd if=/dev/urandom of=sym.key bs=1 count=$(($1 / 8)) 2>/dev/null\n"
  dd if=/dev/urandom of=sym.key bs=1 count=$(($1 / 8)) 2>/dev/null

  printf "> tpm2_loadexternal -G aes -r sym.key -n name.bin -o key.ctx > stdout.yaml\n"
  tpm2_loadexternal -G aes -r sym.key -n name.bin -o key.ctx > stdout.yaml

  printf "> local name1=\`yaml_get_kv \"stdout.yaml\" \"'name'\"\`"
  local name1=`yaml_get_kv "stdout.yaml" "'name'"`
  printf " == $name1\n"
  printf "> local xname1=\`python -c \"printf('{:X}'.format($name1))\"\`"
  local xname1=`python -c "print '{:X}'.format($name1)"`
  printf " == $xname1\n"
  printf "> local xname2=`xxd -u -c 256 -p name.bin`\n"
  local xname2=`xxd -u -c 256 -p name.bin`
  printf "> local name2=\`python -c \"print int(\"$xname2\",16)\"\`"
  local name2=`python -c "print int(\"$xname2\",16)"`
  printf " == $name2\n"

  printf "> test \"$name1\" == \"$name2\""
  test "$name1" = "$name2"
  if [ "$?" = "0" ]; then
    printf " (equal)\n"
  else
    printf " different)\n"
  fi

  printf "> echo \"plaintext\" > \"plain.txt\"\n"
  echo "plaintext" > "plain.txt"

  cat plain.txt

  printf "> tpm2_encryptdecrypt -c key.ctx -I plain.txt -o plain.enc\n"
  tpm2_encryptdecrypt -c key.ctx -I plain.txt -o plain.enc

  printf "> openssl enc -in plain.enc -out plain.dec.ssl -d -K `xxd -p -c 256 sym.key` -iv 0 -aes-$1-cfb\n"
  openssl enc -in plain.enc -out plain.dec.ssl -d -K `xxd -p -c 256 sym.key` -iv 0 -aes-$1-cfb

  printf "> diff plain.txt plain.dec.ssl\n"
  diff plain.txt plain.dec.ssl

  printf "# run_aes_test END\n"
  printf "################################################################################\n"
}

run_ecc_test() {
  printf "################################################################################\n"
  printf "# run_ecc_test START\n"

  #
  # Test loading an OSSL PEM format ECC key, and verifying a signature external
  # to the TPM
  #

  #
  # Generate a NIST P256 Private and Public ECC pem file
  #
  printf "> openssl ecparam -name $1 -genkey -noout -out private.ecc.pem\n"
  openssl ecparam -name $1 -genkey -noout -out private.ecc.pem
  printf "> openssl ec -in private.ecc.pem -out public.ecc.pem -pubout\n"
  openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

  # Generate a hash to sign
  printf "> echo "data to sign" > data.in.raw\n"
  echo "data to sign" > data.in.raw
  printf "> sha256sum data.in.raw | awk '{ print \"000000 \" $1 }' | xxd -r -c 32 > data.in.digest\n"
  sha256sum data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > data.in.digest

  # Load the private key for signing
  printf "> tpm2_loadexternal -Q -G ecc -r private.ecc.pem -o key.ctx\n"
  tpm2_loadexternal -Q -G ecc -r private.ecc.pem -o key.ctx

  # Sign in the TPM and verify with OSSL
  printf "> tpm2_sign -Q -c key.ctx -G sha256 -D data.in.digest -f plain -s data.out.signed\n"
  tpm2_sign -Q -c key.ctx -G sha256 -D data.in.digest -f plain -s data.out.signed
  printf "> openssl dgst -verify public.ecc.pem -keyform pem -sha256 -signature data.out.signed data.in.raw\n"
  openssl dgst -verify public.ecc.pem -keyform pem -sha256 -signature data.out.signed data.in.raw

  # Sign with openssl and verify with TPM but only with the public portion of an object loaded
  printf "> tpm2_loadexternal -Q -G ecc -u public.ecc.pem -o key.ctx\n"
  tpm2_loadexternal -Q -G ecc -u public.ecc.pem -o key.ctx
  printf "> openssl dgst -sha256 -sign private.ecc.pem -out data.out.signed data.in.raw\n"
  openssl dgst -sha256 -sign private.ecc.pem -out data.out.signed data.in.raw
  printf "> tpm2_verifysignature -Q -c key.ctx -G sha256 -m data.in.raw -f ecdsa -s data.out.signed\n"
  tpm2_verifysignature -Q -c key.ctx -G sha256 -m data.in.raw -f ecdsa -s data.out.signed

  printf "# run_ecc_test END\n"
  printf "################################################################################\n"
}

run_tss_test

run_rsa_test 1024
run_rsa_test 2048

run_aes_test 128
run_aes_test 256

run_ecc_test prime256v1

exit 0
