#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <stdio.h>
void process_request(char *query) {
	char *q, arg[160];
	//if (!(q=strstr(query, "op=")))
	//	return;
	//strcpy(arg, q); // query string argument
	//if (strncmp(query,"cpegg",5)) return;
	sprintf(arg,"echo %s",query);
	//strcpy(arg,query);
	system(arg);
	//...
	return;
}
int main(int argc, char *argv[], char *envp[]) {
	char *query = getenv("QUERY_STRING");
	process_request(query);
}
