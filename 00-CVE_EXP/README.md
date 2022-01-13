# CVE Exploit PoC's

PoC exploits for multiple software vulnerabilities.

## Current exploits

- **CVE-2019-18634** (LPE): Stack-based buffer overflow in sudo tgetpass.c when pwfeedback module is enabled
- **CVE-2021-3156** (LPE): Heap-based buffer overflow in sudo sudoers.c when an argv ends with backslash character.
- **CVE-2020-28018** (RCE): Exim Use-After-Free (UAF) in tls-openssl.c leading to Remote Code Execution
- **CVE-2020-9273** (RCE): ProFTPd Use-After-Free (UAF) leading to Post-Auth Remote Code Execution
- **jad OOB write** (CE): JAD out-of-bounds write leading to code execution (No CVE given yet)
