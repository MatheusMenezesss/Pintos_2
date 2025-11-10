#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define ARG_MAX 64

int process_add_file(struct file* f);
struct file* process_get_file(int fd);
void process_close_file(int fd);
tid_t process_execute (const char *exec_string);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


#endif /* userprog/process.h */
