#!/bin/bash

aclocal -I build && automake && autoconf -I build/

./configure --prefix=/usr/local/libec/ 

make && sudo make install
