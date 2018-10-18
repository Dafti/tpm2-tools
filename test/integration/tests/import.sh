#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2017-2018, Intel Corporation
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

cleanup() {
  tpm2_evictcontrol -Q -a o -c parent.ctx 2>/dev/null
  rm -f import_key.ctx  import_key.name  import_key.priv  import_key.pub \
    parent.ctx plain.dec.ssl  plain.enc  plain.txt  sym.key \
    import_rsa_key.pub import_rsa_key.priv import_rsa_key.ctx import_rsa_key.name \
    private.pem public.pem plain.rsa.enc plain.rsa.dec \
    public.pem data.in.raw data.in.digest data.out.signed ticket.out \
    ecc.pub ecc.priv ecc.name ecc.ctx private.ecc.pem public.ecc.pem

  if [ "$1" != "no-shut-down" ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up

run_hmac_import_test() {
  local file_hmac_key=hmac_$2_key.dat
  local file_hmac_key_ctx=hmac_$2_key_ctx.dat
  local file_hmac_key_name=hmac_$2_key_name.dat
  local file_hmac_out=hmac_$2_out.dat
  local file_hmac_stdout=hmac_$2_stdout.dat
  local file_o_hmac_out=o_hmac_$2_out.dat
  printf "################################################################\n"
  printf "# HMAC $2 import test\n"

  printf "> dd if=/dev/urandom of=$file_hmac_key bs=1 count=$(($2/8)) 2>/dev/null\n"
  dd if=/dev/urandom of=$file_hmac_key bs=1 count=$(($2/8)) 2>/dev/null
  local file_hmac_key_size=`stat -c "%s" $file_hmac_key`
  local hmac_key=`xxd -g 0 -ps -c $file_hmac_key_size $file_hmac_key`
  printf "> hmac.key = $hmac_key\n"
  printf "> dd if=/dev/urandom of=random.in bs=1 count=4096 2>/dev/null\n"
  dd if=/dev/urandom of=random.in bs=1 count=4096 2>/dev/null

  printf "> tpm2_import -G hmac -g $name_alg -k $file_hmac_key -C $1 -u import_key.pub -r import_key.priv\n"
  tpm2_import -G hmac -g $name_alg -k $file_hmac_key -C $1 -u import_key.pub -r import_key.priv
  printf "> tpm2_load -C $1 -u import_key.pub -r import_key.priv -n $file_hmac_key_name -o $file_hmac_key_ctx\n"
  tpm2_load -C $1 -u import_key.pub -r import_key.priv -n $file_hmac_key_name -o $file_hmac_key_ctx
  printf "> tpm2_hmac -C $file_hmac_key_ctx -o $file_hmac_out random.in | tee $file_hmac_stdout\n"
  tpm2_hmac -C $file_hmac_key_ctx -o $file_hmac_out random.in | tee $file_hmac_stdout

  printf "> openssl dgst -sha256 -mac HMAC -macopt hexkey:$hmac_key -binary -out $file_o_hmac_out random.in\n"
  openssl dgst -sha$2 -mac HMAC -macopt hexkey:$hmac_key -binary -out $file_o_hmac_out random.in

  printf "> diff $file_hmac_out $file_o_hmac_out\n"
  diff $file_hmac_out $file_o_hmac_out > /dev/null && printf "Equal\n" || printf "Different\n"
  local file_hmac_out_size=`stat -c "%s" $file_hmac_out`
  local file_o_hmac_out_size=`stat -c "%s" $file_o_hmac_out`
  printf "tpm     = `xxd -g 0 -ps -c $file_hmac_out_size $file_hmac_out`\n"
  printf "openssl = `xxd -g 0 -ps -c $file_o_hmac_out_size $file_o_hmac_out`\n"

  printf "# HMAC import test done\n"
  printf "################################################################\n"
}

run_aes_import_test() {
  printf "################################################################\n"
  printf "# AES $2 import test\n"

  printf "> dd if=/dev/urandom of=sym.key bs=1 count=$2 2>/dev/null\n"
  dd if=/dev/urandom of=sym.key bs=1 count=$2 2>/dev/null

  #Symmetric Key Import Test
  printf "> tpm2_import -Q -G aes -g $name_alg -k sym.key -C $1 -u import_key.pub -r import_key.priv\n"
  tpm2_import -Q -G aes -g $name_alg -k sym.key -C $1 -u import_key.pub -r import_key.priv

  printf "> tpm2_load -Q -C $1 -u import_key.pub -r import_key.priv -n import_key.name -o import_key.ctx\n"
  tpm2_load -Q -C $1 -u import_key.pub -r import_key.priv -n import_key.name -o import_key.ctx

  printf "> echo \"plaintext\" > plain.txt\n"
  echo "plaintext" > plain.txt

  printf "> tpm2_encryptdecrypt -c import_key.ctx  -I plain.txt -o plain.enc\n"
  tpm2_encryptdecrypt -c import_key.ctx  -I plain.txt -o plain.enc

  printf "> openssl enc -in plain.enc -out plain.dec.ssl -d -K `xxd -c $2 -p sym.key` -iv 0 -aes-$((8*$2))-cfb\n"
  openssl enc -in plain.enc -out plain.dec.ssl -d -K `xxd -c $2 -p sym.key` -iv 0 -aes-$((8*$2))-cfb

  printf "> diff plain.txt plain.dec.ssl\n"
  diff plain.txt plain.dec.ssl
  printf "# AES $2 import test done\n"
  printf "################################################################\n"
}

run_rsa_import_test() {

  #Asymmetric Key Import Test
  printf "> openssl genrsa -out private.pem $2\n"
  openssl genrsa -out private.pem $2
  printf "> openssl rsa -in private.pem -pubout > public.pem\n"
  openssl rsa -in private.pem -pubout > public.pem

  # Test an import without the parent public info data to force a readpublic
  printf "> tpm2_import -Q -G rsa -g $name_alg -k private.pem -C $1 -u import_rsa_key.pub -r import_rsa_key.priv\n"
  tpm2_import -Q -G rsa -g $name_alg -k private.pem -C $1 -u import_rsa_key.pub -r import_rsa_key.priv

  printf "> tpm2_load -Q -C $1 -u import_rsa_key.pub -r import_rsa_key.priv -n import_rsa_key.name -o import_rsa_key.ctx\n"
  tpm2_load -Q -C $1 -u import_rsa_key.pub -r import_rsa_key.priv -n import_rsa_key.name -o import_rsa_key.ctx

  printf "> openssl rsa -in private.pem -out public.pem -outform PEM -pubout\n"
  openssl rsa -in private.pem -out public.pem -outform PEM -pubout

  printf "> echo \"plaintext\" > plain.txt\n"
  echo "plaintext" > plain.txt

  printf "> openssl rsautl -encrypt -inkey public.pem -pubin -in plain.txt -out plain.rsa.enc\n"
  openssl rsautl -encrypt -inkey public.pem -pubin -in plain.txt -out plain.rsa.enc

  printf "> tpm2_rsadecrypt -c import_rsa_key.ctx -I plain.rsa.enc -o plain.rsa.dec\n"
  tpm2_rsadecrypt -c import_rsa_key.ctx -I plain.rsa.enc -o plain.rsa.dec

  printf "> diff plain.txt plain.rsa.dec\n"
  diff plain.txt plain.rsa.dec

  # test verifying a sigature with the imported key, ie sign in tpm and verify with openssl
  printf "> echo \"data to sign\" > data.in.raw\n"
  echo "data to sign" > data.in.raw

  printf "> sha256sum data.in.raw | awk '{ print \"000000 \" $1 }' | xxd -r -c 32 > data.in.digest\n"
  sha256sum data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > data.in.digest

  printf "> tpm2_sign -Q -c import_rsa_key.ctx -G sha256 -D data.in.digest -f plain -s data.out.signed\n"
  tpm2_sign -Q -c import_rsa_key.ctx -G sha256 -D data.in.digest -f plain -s data.out.signed

  printf "> openssl dgst -verify public.pem -keyform pem -sha256 -signature data.out.signed data.in.raw\n"
  openssl dgst -verify public.pem -keyform pem -sha256 -signature data.out.signed data.in.raw

  # Sign with openssl and verify with TPM
  printf "> openssl dgst -sha256 -sign private.pem -out data.out.signed data.in.raw\n"
  openssl dgst -sha256 -sign private.pem -out data.out.signed data.in.raw

  # Verify with the TPM
  printf "> tpm2_verifysignature -Q -c import_rsa_key.ctx -G sha256 -m data.in.raw -f rsassa -s data.out.signed -t ticket.out\n"
  tpm2_verifysignature -Q -c import_rsa_key.ctx -G sha256 -m data.in.raw -f rsassa -s data.out.signed -t ticket.out
}

run_ecc_import_test() {
  #
  # Test loading an OSSL PEM format ECC key, and verifying a signature external
  # to the TPM
  #

  #
  # Generate a Private and Public ECC pem file
  #
  printf "> openssl ecparam -name $2 -genkey -noout -out private.ecc.pem\n"
  openssl ecparam -name $2 -genkey -noout -out private.ecc.pem
  printf "> openssl ec -in private.ecc.pem -out public.ecc.pem -pubout\n"
  openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

  # Generate a hash to sign
  printf "> echo \"data to sign\" > data.in.raw\n"
  echo "data to sign" > data.in.raw
  printf "> sha256sum data.in.raw | awk '{ print \"000000 \" $1 }' | xxd -r -c 32 > data.in.digest\n"
  sha256sum data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > data.in.digest

  printf "> tpm2_import -Q -G ecc -g $name_alg -k private.ecc.pem -C $1 -u ecc.pub -r ecc.priv\n"
  tpm2_import -Q -G ecc -g $name_alg -k private.ecc.pem -C $1 -u ecc.pub -r ecc.priv

  printf "> tpm2_load -Q -C $1 -u ecc.pub -r ecc.priv -n ecc.name -o ecc.ctx\n"
  tpm2_load -Q -C $1 -u ecc.pub -r ecc.priv -n ecc.name -o ecc.ctx

  # Sign in the TPM and verify with OSSL
  printf "> tpm2_sign -Q -c ecc.ctx -G sha256 -D data.in.digest -f plain -s data.out.signed\n"
  tpm2_sign -Q -c ecc.ctx -G sha256 -D data.in.digest -f plain -s data.out.signed
  printf "> openssl dgst -verify public.ecc.pem -keyform pem -sha256 -signature data.out.signed data.in.raw\n"
  openssl dgst -verify public.ecc.pem -keyform pem -sha256 -signature data.out.signed data.in.raw

  # Sign with openssl and verify with TPM.
  printf "> openssl dgst -sha256 -sign private.ecc.pem -out data.out.signed data.in.raw\n"
  openssl dgst -sha256 -sign private.ecc.pem -out data.out.signed data.in.raw
  printf "> tpm2_verifysignature -Q -c ecc.ctx -G sha256 -m data.in.raw -f ecdsa -s data.out.signed\n"
  tpm2_verifysignature -Q -c ecc.ctx -G sha256 -m data.in.raw -f ecdsa -s data.out.signed
}

run_test() {
  cleanup "no-shut-down"

  parent_alg=$1
  name_alg=$2

  printf "> tpm2_createprimary -Q -G \"$parent_alg\" -g \"$name_alg\" -a o -o parent.ctx\n"
  tpm2_createprimary -Q -G "$parent_alg" -g "$name_alg" -a o -o parent.ctx

  run_hmac_import_test parent.ctx 256
  run_hmac_import_test parent.ctx 384
  run_hmac_import_test parent.ctx 512

  # 128 bit AES is 16 bytes
  run_aes_import_test parent.ctx 16
  # 256 bit AES is 32 bytes
  run_aes_import_test parent.ctx 32

  run_rsa_import_test parent.ctx 1024
  run_rsa_import_test parent.ctx 2048

  run_ecc_import_test parent.ctx prime256v1
}

#
# Run the tests against:
#   - RSA2048 with AES CFB 128 and 256 bit parents
#   - SHA256 object (not parent) name algorithms
#
parent_algs=("rsa2048:aes128cfb" "rsa2048:aes256cfb")
halgs=`populate_hash_algs 'and alg != "sha1"'`
echo "halgs: $halgs"
for pa in "${parent_algs[@]}"; do
  for name in $halgs; do
    echo "$pa - $name"
    run_test "$pa" "$name"
  done;
done;

exit 0
