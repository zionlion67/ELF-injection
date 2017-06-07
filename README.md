# ELF-infection
Static code injection using text padding and reverse text extension.

Build:

gcc -nostdlib text\_pad\_infect.c -o tpi

gcc -nostdlib reverse\_text\_infect -o rti

Example:

$ cp /bin/ls .

$ ./tpi ./ls

The local `ls` now displays 'LSE' before executing.
