#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    
    if (geteuid() == 0) {
        setuid(0);
        setgid(0);
        puts("[+] I am root");
        system("bash");
    }

}
