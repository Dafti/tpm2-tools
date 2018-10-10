#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016-2018, THALES
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

start_up

cleanup() {

  rm -f policy.bin obj.pub pub.out

  ina "$@" "keep-context"
  if [ $? -ne 0 ]; then
    rm -f context.out
  fi

  ina "$@" "no-shut-down"
  if [ $? -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

cleanup "no-shut-down"

tpm2_clear -Q

gAlgs=(`populate_hash_algs 'and alg != "keyedhash"'`)
gAlg=${gAlgs[-1]}
GAlg=rsa
Atype=p

tpm2_createprimary -a $Atype -g $gAlg -G $GAlg -o context.out
tpm2_readpublic -c context.out | tee primary.pub
tpm2_evictcontrol -a $Atype -c context.out -p 0x81010003
tpm2_readpublic -c 0x81010003 | tee primary_handle.pub

diff primary.pub primary_handle.pub

# tpm2_create -C context.out -g sha256 -G aes256cbc -u key.pub -r key.priv
# tpm2_load -C context.out -u key.pub -r key.priv -o key.ctx

exit 0
