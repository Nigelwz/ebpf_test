#ifndef _COMMON_H_
#define _COMMON_H_


#define PATH_LEN 512
struct event {
	int pid;
	char path_name[PATH_LEN];
};

#endif
