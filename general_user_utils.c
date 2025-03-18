#include <stdio.h> // fdopen, fgets, fopen, snprintf
#include <string.h>
#include <stdlib.h> //atoi

int username_to_uid(char *username) {
    FILE *fp = fopen("/etc/passwd", "r");
    char buf[128];
    int uid = -1;
    while(fgets(buf, 128, fp) != NULL) {
    	char *start = strtok(buf, ":\n");
    	if(strcmp(start, username) != 0)
    	    continue;
    	    
    	for(int i = 0; i < 2; i++)
    	    start = strtok(NULL, ":\n");
    	uid = atoi(start);
    	break;
    }
	fclose(fp);
    return uid;
}