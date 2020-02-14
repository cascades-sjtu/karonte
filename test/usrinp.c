#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
int serve_request(char *req) {
	setenv("QUERY_STRING", req, 1);
	int ret=execv("/home/karonte/dev/karonte/test/datsink",NULL);
	printf("----%d %s----",ret,strerror(ret));
}
int main(int argc, char *argv[], char *envp[]){
	char buf[1024]={0};
	read(0,buf,1024);
	serve_request(buf);
	return 0;
}
