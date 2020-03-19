//gcc -m32 -fno-stack-protector -o ./32/bof_static bof_static.c
//gcc -fno-stack-protector -o ./64/bof_static bof_static.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln(){

	char buf[0x20];
	read(0, buf, 0x100);

}

void init_io(){

	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);

}

int main(int argc, char **argv){


	init_io();
	//puts("Buffer overflow task");
	//printf("input:");
	vuln();

}