#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <debug.h>
#include <user/syscall.h>

static void syscall_handler (struct intr_frame *);
void set_arg(struct intr_frame * f, int *arg, int n)
{
    int i;
    for (i =0; i<n;i++)
    {
        arg[i] = *((int*)f->esp + i + 1);
    }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[3];
  //set_arg(struct intr_frame * f, int *arg, int n);
  
  switch (*(int *)f->esp)
  {
      case SYS_HALT:
          {
            //  printf("helt call!\n");
              halt();
              break;
          }
      case SYS_EXIT:
          {
    //          printf("exit call!\n");
              set_arg(f,arg,1);
              exit(arg[0]);
              break;
          }
      case SYS_EXEC:
          {
             // printf("exec call!\n");
              set_arg(f,arg,1);
              exec(arg[0]);
              break;
          }
      case SYS_WAIT:
          {
             // printf("wait call!\n");
              set_arg(f,arg,1);
              wait(arg[1]);
              break;
          }
      case SYS_CREATE:
          {
             // printf("crete call!\n");
              break;
          }
      case SYS_REMOVE:
          {
             // printf("remove call!\n");
              break;
          }
      case SYS_OPEN:
          {
             // printf("open call!\n");
              break;
          }
      case SYS_FILESIZE:
          {
             // printf("filesize call!\n");
              break;
          }
      case SYS_READ:
          {
             // printf("read call!\n");
              break;
          }
      case SYS_WRITE:
          {
    //          printf("write call!\n");
              set_arg(f,arg,3);
              write(arg[0],arg[1],arg[2]);
              break;
          }
      case SYS_SEEK:
          {
              printf("seek call!\n");
              break;
          }
      case SYS_TELL:
          {
              printf("tell call!\n");
              break;
          }
      case SYS_CLOSE:
          {
              printf("close call!\n");
              break;
          }

  }
  //printf ("system call!\n");
  //thread_exit ();
}
void halt()
{
    shutdown_power_off();
}
//status 0 == success other == error
void exit(int status)
{
    struct thread* cur = thread_current();
    struct thread* parent = cur -> parent;
    if(parent != NULL)
    {
      struct child_elem * ch = get_ch_elem(&parent->ch_list, cur->tid);
      ch -> status = status;
      ch -> exit = true;
    }
    printf("%s: exit(%d)\n",cur -> name, status);
    thread_exit();//no return
}
pid_t exec(const char* file)
{
    pid_t p = process_execute(file);
    return p;
}
int wait(pid_t pid)
{

    struct child_elem* ch = get_ch_elem(&thread_current()->ch_list, pid);
    if(pid != -1 && ch == NULL)//wrong pid
        return -1;

    if(ch->exit)//already finish
        return ch->status;

    if(ch->waiting)//already waiting
        return -1;
    
    if(!thread_exist(pid))//die by kernel
        return -1;
    
    //enum intr_level old_level = intr_disable ();
    struct thread* cur = thread_current();
    ch -> waiting = true;

    while( !ch->exit && thread_exist(pid) )
    {
            barrier();
    }
    ch -> waiting = false;
    //have to remove child_elem


    //intr_set_level (old_level);
    return ch->status;  
}
bool create(const char* file, unsigned initial_size)
{
    return 0;
}
bool remove(const char* file)
{

    return 0;
}
int open(const char* file)
{
    return 0;
}
int filesize(int fd)
{
    return 0;
}
int read(int fd, void *buffer, unsigned size)
{
    return 0;
}
int write(int fd, const void *buffer, unsigned size)
{
    putbuf(buffer,size);
    return size;
}
void seek(int fd, unsigned position)
{
    return 0;
}
unsigned tell(int fd)
{
    return 0;
}
void close(int fd)
{
    return 0;
}
