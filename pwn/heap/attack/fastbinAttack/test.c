#include <stdio.h>
int main(){
	unsigned long* chunk1=malloc(0x40); //0x602000
	unsigned long* chunk2=malloc(0x40); //0x602050
	free(chunk1);
	free(chunk2);
	*(chunk1+0x9)=0x54;
	malloc(0x40);
	return 0;
}
