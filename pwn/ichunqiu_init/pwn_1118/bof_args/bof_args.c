//gcc -m32 -fno-stack-protector -o ./32/bof_args bof_args.c
//gcc -fno-stack-protector -o ./64/bof_args bof_args.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char cmd[0x20];

void backdoor(char *command){
	system(command);
}

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
	puts("Buffer overflow task");
	printf("command:");
	read(0, cmd, 0x20);
	printf("input:");
	vuln();

}