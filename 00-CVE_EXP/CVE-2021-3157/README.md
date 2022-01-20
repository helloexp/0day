# CVE-2021-3156
PoC for CVE-2021-3156 (sudo heap overflow). Exploit by @gf_256 aka cts. Thanks to r4j from super guesser for help. Credit to Braon Samedit of Qualys for the [original advisory](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt).

[Demo video](https://twitter.com/gf_256/status/1355354178588180481)

# Instructions

1. wget/curl
2. tune RACE_SLEEP_TIME
3. gcc exploit.c
4. cp /etc/passwd fakepasswd
5. modify fakepasswd so your uid is 0
6. ./a.out

Tested on Ubuntu 18.04 (sudo 1.8.21p2) and 20.04 (1.8.31)

this bug freaking sucked to PoC, it took like 3 sisyphean days and then suddenly today I just got insanely lucky
