# ndn-drop Build Instructions

This document describes how to build and install ndn-drop.

## Prerequisites

-  Install the [ndn-cxx](https://named-data.net/doc/ndn-cxx/current/) library and its prerequisites.
   Please see [Getting Started with ndn-cxx](https://named-data.net/doc/ndn-cxx/current/INSTALL.html)
   for how to install ndn-cxx.
   Note: If you have installed ndn-cxx from a binary package, please make sure development headers
   are installed (e.g., if using Ubuntu PPA, the `libndn-cxx-dev` package is needed).

   Any operating system and compiler supported by ndn-cxx is supported by ndn-tools.

-  `libpcap`

    Comes with the base system on macOS.

    On Ubuntu:

        sudo apt install libpcap-dev

    On CentOS and Fedora:

        sudo dnf config-manager --enable PowerTools  # CentOS only
        sudo dnf install libpcap-devel

## Build Steps

To configure, compile, and install ndn-tools, type the following commands
in ndn-tools source directory:

    ./waf configure
    ./waf
    sudo ./waf install

To uninstall ndn-drop:

    sudo ./waf uninstall
