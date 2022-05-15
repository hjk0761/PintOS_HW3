#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "devices/block.h"
#include "filesys/off_t.h"

static void syscall_handler (struct intr_frame *);
void exit (int status);
int write (int fd, const void *buffer, unsigned size);

struct file{
  struct inode *inode;
  off_t pos;
  bool deny_write;
};




void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("system call!\n");
  //thread_exit ();

  //printf("syscall: %d\n", *(uint32_t *)(f->esp));
  //hex_dump(f->esp, f->esp, 100, 1);
  void *esp = f->esp;

  switch (*(uint32_t *)esp){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      //exit(*(uint32_t *)(f->esp + 4));
      exit(*(uint32_t *)(esp + 4));
      break;
    case SYS_EXEC:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      f->eax = exec((const char *)*(uint32_t *)(esp + 4));
      break;
    case SYS_WAIT:
      //if(!is_user_vaddr(esp + 4)) exit(-1);
      f->eax = wait((pid_t *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CREATE:
      if(!is_user_vaddr(f->esp + 4)) exit(-1);
      f->eax = create((const char *)*(uint32_t *)(esp + 4), (const char *)*(uint32_t *)(esp + 8));
      break;
    case SYS_REMOVE:
      if(!is_user_vaddr(f->esp + 4)) exit(-1);
      f->eax = remove((const char *)*(uint32_t *)(esp + 4));
      break;
    case SYS_OPEN:
      if(!is_user_vaddr(f->esp + 4)) exit(-1);
      f->eax = open((const char *)*(uint32_t *)(esp + 4));
      break;
    case SYS_FILESIZE:
      if(!is_user_vaddr(f->esp + 4)) exit(-1);
      f->eax = filesize((int)*(uint32_t *)(esp + 4));
      break;
    case SYS_READ:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      f->eax = read((int)*(uint32_t *)(esp + 4), (void *)*(uint32_t *)(esp + 8), (unsigned)*((uint32_t *)(esp + 12)));
      break;
    case SYS_WRITE:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      f->eax = write((int)*(uint32_t *)(esp + 4), (void *)*(uint32_t *)(esp + 8), (unsigned)*((uint32_t *)(esp + 12)));
      break;
    case SYS_SEEK:
      if(!is_user_vaddr(f->esp + 4)) exit(-1);
      seek((int)*(uint32_t *)(esp + 4), (unsigned)*((uint32_t *)(esp + 8)));
      break;
    case SYS_TELL:
      if(!is_user_vaddr(f->esp + 4)) exit(-1);
      f->eax = tell((int)*(uint32_t *)(esp + 4));
      break;
    case SYS_CLOSE:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      close((int)*(uint32_t *)(esp + 4));
      break;
    default:
      exit(-1);
      break;
  }

}

void halt (void)
{
  shutdown_power_off();
}

void exit (int status)
{

  int i;
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  for(i = 3; i < 128; i++){
    if(thread_current()->fd[i] != NULL) close(i);
  }
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
  if(file == NULL) exit(-1);
  if(!is_user_vaddr(file)) exit(-1);
  return filesys_create(file, initial_size);
}

bool remove (const char *file)
{
  if(file == NULL) exit(-1);
  if(!is_user_vaddr(file)) exit(-1);
  return filesys_remove(file);
}

int open (const char *file)
{
  int i;
  if(!is_user_vaddr(file)) exit(-1);
  if(file == NULL) return -1;
  struct file *fi = filesys_open(file);
  if(fi == NULL) return -1;
  else{
    for(i = 3; i < 128; i++){
      if(thread_current()->fd[i] == NULL){
        if(strcmp(thread_current()->name, file) == 0){
          file_deny_write(fi);
        }
        thread_current()->fd[i] = fi;
        return i;
      }
    }
  }
  return -1;
}

int filesize (int fd)
{
  if(thread_current()->fd[fd] == NULL) exit(-1);
  else return file_length(thread_current()->fd[fd]);
}

int read (int fd, void *buffer, unsigned size)
{
  if(!is_user_vaddr(buffer)) exit(-1);
  int i;
  if(fd == 0){
    for(i = 0; i < size; i++){
      if(((char *)buffer)[i] == '\0') break;
    }
  }
  else{
    if(thread_current()->fd[fd] == NULL) exit(-1);
    else return file_read(thread_current()->fd[fd], buffer, size);
  }
  return i;
}

int write (int fd, const void *buffer, unsigned size)
{
  if(!is_user_vaddr(buffer)) exit(-1);
  if(fd == 1){
    putbuf(buffer, size);
    return size;
  }
  else if(fd > 2){
    if(thread_current()->fd[fd] == NULL) exit(-1);
    if(thread_current()->fd[fd]->deny_write){
      file_deny_write(thread_current()->fd[fd]);
    }
    return file_write(thread_current()->fd[fd], buffer, size);
  }
  return -1;
}

void seek (int fd, unsigned position)
{
  if(thread_current()->fd[fd] == NULL) exit(-1);
  else return file_seek(thread_current()->fd[fd], position);
}

unsigned tell (int fd)
{
  if(thread_current()->fd[fd] == NULL) exit(-1);
  else return file_tell(thread_current()->fd[fd]);
}

void close (int fd)
{
  struct file* fi;
  if(thread_current()->fd[fd] == NULL) exit(-1);
  fi = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  return file_close(fi);
}
