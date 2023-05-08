#include<stdio.h>
#include<stdlib.h>

int main() {
	FILE *fp;
	
	fp = fopen("infile.txt", "w");
	fprintf(fp, "Hello world");
	fclose(fp);
	return 0;
}
