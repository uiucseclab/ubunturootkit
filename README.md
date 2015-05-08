# ubunturootkit

This is a rootkit designed for Ubuntu 14.04 32-bit.
CS 460 Spring 2015 - Security Lab

Contributors:
    Hiroshi Fujii
    David Jiang
    Alex Mitsdarfer
    Shareefah Williams

Note: There are some directory-specific/hardcoded directories in the source.
      The current code is expecting the module to be at
      /home/cs460/dev/rootkit/rootkit.c

To install and run:
    0. You need Linux headers to compile:
        apt-get install linux-headers-$(uname -r)
    1. Make
    2. sudo insmod rootkit.ko
    3. ???
    4. Profit (but not for you)

For obvious reasons, it's not recommended to run this on a computer you care about.
Use a VM.
