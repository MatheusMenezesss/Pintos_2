#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/input.h"

/* Lock para sincronizar acesso ao sistema de arquivos */
struct lock filesys_lock;

/* Declarações de funções */
void exit(int status);
tid_t exec(const char *file_name);
int wait(tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

static void syscall_handler (struct intr_frame *);


/* === checadores seguros === */
static void
check_user_pointer(const void *uaddr) {
  if (uaddr == NULL || !is_user_vaddr(uaddr) ||
      pagedir_get_page(thread_current()->pagedir, uaddr) == NULL) {
    exit(-1);
  }
}

static void
check_user_buffer(const void *buffer, unsigned size) {
  if (size == 0) return;
  const char *start = (const char *) buffer;
  const char *end = start + size - 1;
  if (!is_user_vaddr(start) || !is_user_vaddr(end))
    exit(-1);
  void *page = pg_round_down(start);
  while ((const char *) page <= end) {
    if (pagedir_get_page(thread_current()->pagedir, page) == NULL)
      exit(-1);
    page = (char *) page + PGSIZE;
  }
}

static void
check_user_string(const char *us) {
  if (us == NULL) exit(-1);
  if (!is_user_vaddr(us)) exit(-1);

  const char *p = us;
  void *page = pg_round_down(p);
  while (true) {
    if (pagedir_get_page(thread_current()->pagedir, page) == NULL)
      exit(-1);
    const char *page_end = (const char *) page + PGSIZE;
    for (; p < page_end; p++) {
      if (!is_user_vaddr(p))
        exit(-1);
      if (*p == '\0') return;
    }
    page = (char *) page + PGSIZE;
  }
}

/* === inicialização === */
void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* === tratador de syscalls (seguro) === */
static void
syscall_handler (struct intr_frame *f) 
{
  if (!f || !f->esp)
    thread_exit();

  /* valida o ponteiro para o primeiro argumento (número da syscall na pilha) */
  check_user_pointer(f->esp);
  int syscall_num = *(int *)f->esp;

  switch (syscall_num) {
    case SYS_EXIT: {
      check_user_pointer(f->esp + 4);
      int status = *(int *)(f->esp + 4);
      exit(status);
      break;
    }

    case SYS_EXEC: {
      check_user_pointer(f->esp + 4);
      const char *cmd = (const char *) *(uint32_t *)(f->esp + 4);
      check_user_string(cmd);
      f->eax = exec(cmd);
      break;
    }

    case SYS_WAIT: {
      check_user_pointer(f->esp + 4);
      tid_t pid = (tid_t) *(uint32_t *)(f->esp + 4);
      f->eax = wait(pid);
      break;
    }

    case SYS_CREATE: {
      check_user_pointer(f->esp + 4);
      check_user_pointer(f->esp + 8);
      const char *file_name = (const char *) *(uint32_t *)(f->esp + 4);
      unsigned initial_size = *(uint32_t *)(f->esp + 8);
      check_user_string(file_name);
      f->eax = create(file_name, initial_size);
      break;
    }

    case SYS_REMOVE: {
      check_user_pointer(f->esp + 4);
      const char *rm_name = (const char *) *(uint32_t *)(f->esp + 4);
      check_user_string(rm_name);
      f->eax = remove(rm_name);
      break;
    }

    case SYS_OPEN: {
      check_user_pointer(f->esp + 4);
      const char *op_name = (const char *) *(uint32_t *)(f->esp + 4);
      check_user_string(op_name);
      f->eax = open(op_name);
      break;
    }

    case SYS_FILESIZE: {
      check_user_pointer(f->esp + 4);
      int fd = (int)*(uint32_t*)(f->esp + 4);
      f->eax = filesize(fd);
      break;
    }

    case SYS_READ: {
      check_user_pointer(f->esp + 4);
      check_user_pointer(f->esp + 8);
      check_user_pointer(f->esp + 12);

      int fd = (int)*(uint32_t*)(f->esp + 4);
      void *buffer = (void *) *(uint32_t *)(f->esp + 8);
      unsigned size = *(uint32_t *)(f->esp + 12);

      check_user_buffer(buffer, size);
      f->eax = read(fd, buffer, size);
      break;
    }

    case SYS_WRITE: {
      check_user_pointer(f->esp + 4);
      check_user_pointer(f->esp + 8);
      check_user_pointer(f->esp + 12);

      int fd = (int)*(uint32_t*)(f->esp + 4);
      const void *buffer = (const void *) *(uint32_t *)(f->esp + 8);
      unsigned size = *(uint32_t *)(f->esp + 12);

      check_user_buffer(buffer, size);
      f->eax = write(fd, buffer, size);
      break;
    }

    default:
      thread_exit();
      break;
  }
}

/* === implementações das syscalls (simplificadas) === */

int open(const char* file){
  int fd;
  struct file* f;

  if (file == NULL) exit(-1);

  lock_acquire(&filesys_lock);
  f = filesys_open(file);
  if (f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  fd = process_add_file(f);
  lock_release(&filesys_lock);
  return fd;
}

int read(int fd, void *buffer, unsigned int size){
  int result = 0;

  if (fd < 0 || fd == 1 || fd >= FDTABLE_SIZE) exit(-1);

  lock_acquire(&filesys_lock);
  if (fd == 0){ /* stdin */
    for (int i = 0; i < (int)size; i++) {
      int c = input_getc();
      ((uint8_t*)buffer)[i] = (uint8_t)c;
      result++;
    }
  } else {
    struct file* f = process_get_file(fd);
    if (f == NULL) {
      lock_release(&filesys_lock);
      exit(-1);
    }
    result = file_read(f, buffer, size);
  }
  lock_release(&filesys_lock);
  return result;
}

int write(int fd, const void* buffer, unsigned int size){
  int file_write_result;
  struct file* f;

  if (fd < 0 || fd == 0 || fd >= FDTABLE_SIZE) exit(-1);

  lock_acquire(&filesys_lock);
  if (fd == 1) {
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  } else {
    f = process_get_file(fd);
    if (f == NULL) {
      lock_release(&filesys_lock);
      exit(-1);
    }
    file_write_result = file_write(f, buffer, size);
    lock_release(&filesys_lock);
    return file_write_result;
  }
}

bool create(const char* file, unsigned initial_size){
  if (file == NULL) exit(-1);
  lock_acquire(&filesys_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return result;
}

bool remove(const char* file){
  if (file == NULL) exit(-1);
  lock_acquire(&filesys_lock);
  bool result = filesys_remove(file);
  lock_release(&filesys_lock);
  return result;
}

void close(int fd){
  process_close_file(fd);
}

int filesize(int fd){
  struct file* f = process_get_file(fd);
  if (f == NULL) exit(-1);
  return file_length(f);
}

void seek(int fd, unsigned position){
  struct file* f = process_get_file(fd);
  if (f == NULL) exit(-1);
  file_seek(f, position);
}

unsigned int tell(int fd){
  struct file* f = process_get_file(fd);
  if (f == NULL) exit(-1);
  return file_tell(f);
}

/* === funções de processo / utilitárias === */
void exit(int status){
  struct thread* cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

tid_t exec(const char* file_name){
  return process_execute(file_name);
}

int wait(tid_t pid){
  return process_wait(pid);
}
