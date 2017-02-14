# Stratosphere LibSlips

# Description
This library, called Stratosphere LibSlips is a C library that implements the Stratosphere IPS detection as a library for other programs. It is a migration of the python code of the Stratosphere Linux IPS made by Cisco systems with the intention of working with a future version of Snort. For more information about the Stratosphere project please see https://stratosphereips.org
This library is published under LGPLv2.

# Version
The version of this library is 0.1, which is an alpha version.

# Authors
This version of Stratosphere slips in C was migrated by Sachin Vernekar (savernek [at] cisco.com) and Urvesh Devani (udevani [at] cisco.com). See the CONTRIBUTORS files for a complete list of people involved in this project. The original author of the Stratosphere Slips python program is Sebastian Garcia (sebastian.garcia@agents.fel.cvut.cz and eldraco@gmail.com).


## Install

- Only  necessary when building from the git repository.

    bootstrap.sh

    ./configure
    make
    sudo make install (optional for testing purposes)

## Run

- First you have to edit the file slips.conf to add the path to your binetflow dataset, then do:

    cd code
    ./slips slips.conf
