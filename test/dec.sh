#!/bin/bash

TMP=$(mktemp)
tr -d ' \n' | xxd -r -ps > $TMP
test/decrypt $TMP
