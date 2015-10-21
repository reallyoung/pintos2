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
#include "threads/vaddr.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
unsigned add_trans(const void* add);
struct lock file_lock;
/*
static bool check_illegal((const void*)ptr)
{
    if(!is_user_vaddr((const void *)ptr) || (const void*)ptr < 0x08048000)
        return false;
    else
        return true;
}
*/
void set_arg(struct intr_frame * f, unsigned *arg, int n)
{
    unsigned i;
    unsigned* ptr;
    for (i =0; i<n;i++)
    {
        ptr = (unsigned*)f->esp + i +1;
        if(!is_user_vaddr((const void*)ptr)||
                (const void*)ptr < 0x08048000)
            exit(-1);

        arg[i] = *((unsigned*)f->esp + i + 1);
    }
}
/*
bool check_illegal((const void*) ptr)
{
     if(!is_user_vaddr((const void *)ptr)||(const void*)ptr < 0x08048000)
         return false;
     else
         return true;
}
*/
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  unsigned arg[3];
  //set_arg(struct intr_frame * f, int *arg, int n);
 
  if(!is_user_vaddr((const void*)f->esp)||
          (const void*)f->esp < 0x08048000)
     exit(-1);

  switch (*(unsigned *)f->esp)
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
              //arg[0] is kernel pointer 
              //it has to be convert
              arg[0] = add_trans((const void*) arg[0]);
              f->eax = exec((const char*)arg[0]);
              break;
          }
      case SYS_WAIT:
          {
             // printf("wait call!\n");
              set_arg(f,arg,1);
              f -> eax = wait(arg[0]);
              break;
          }
      case SYS_CREATE:
          {
             // printf("crete call!\n");
              set_arg(f,arg,2);
              arg[0] = add_trans((const void*) arg[0]);
              f->eax = create((const char*)arg[0], arg[1]);
              break;
          }
      case SYS_REMOVE:
          {
             // printf("remove call!\n");
             set_arg(f,arg,1);
             arg[0] = add_trans((const void*) arg[0]);
             f->eax = remove((const char*)arg[0]);
              break;
          }
      case SYS_OPEN:
          {
             // printf("open call!\n");
             set_arg(f,arg,1);
             arg[0] = add_trans((const void*) arg[0]);
             f->eax = open((const char*)arg[0]);
              break;
          }
      case SYS_FILESIZE:
          {
             // printf("filesize call!\n");
              set_arg(f,arg,1);
              f->eax = filesize(arg[0]);
              break;
          }
      case SYS_READ:
          {
             // printf("read call!\n");
              set_arg(f,arg,3);
              arg[1] = add_trans((const void*) arg[1]);
              f->eax = read(arg[0],(const void*)arg[1],arg[2]);
              break;
          }
      case SYS_WRITE:
          {
    //          printf("write call!\n");
              set_arg(f,arg,3);
              arg[1] = add_trans((const void*) arg[1]);
              f->eax = write(arg[0],(const void*)arg[1],arg[2]);
              break;
          }
      case SYS_SEEK:
          {
            //  printf("seek call!\n");
              set_arg(f,arg,2);
              seek(arg[0],arg[1]);
              break;
          }
      case SYS_TELL:
          {
              //printf("tell call!\n");
              set_arg(f,arg,1);
              f->eax = tell(arg[0]);
              break;
          }
      case SYS_CLOSE:
          {
              //printf("close call!\n");
              set_arg(f,arg,1);
              close(arg[0]);
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
      struct child_elem * ch = cur->my_child_elem;
      ch -> status = status;
      ch -> exit = true;
    }
    printf("%s: exit(%d)\n",cur -> name, status);
    thread_exit();//no return
}
pid_t exec(const char* file)
{
    pid_t p = process_execute(file);
    struct thread* th = thread_current();
    struct child_elem* ch = get_ch_elem(&th->ch_list, p);
    if(ch->load == false)
        thread_yield();

    if(ch->load_fail)
        return -1;
    else
    {
       // printf("exec return %d\n",p);
        return p;
    }
}
int wait(pid_t pid)
{
    int s;
    struct child_elem* ch = get_ch_elem(&thread_current()->ch_list, pid);
    
    if( ch == NULL)//wrong pid
        return -1;

    else if(ch->exit)//already finish
    {
        s = ch->status;
        list_remove(&ch->elem);
        free(ch);
        return s;
    }
    else if(ch->waiting)//already waiting
        return -1;
    
    else if(!thread_exist(pid))//die by kernel
        return -1;
    
    //enum intr_level old_level = intr_disable ();
    struct thread* cur = thread_current();
    ch -> waiting = true;

    while( !ch->exit && thread_exist(pid) )
    {
        thread_yield();
    }
    ch -> waiting = false;
    //have to remove child_elem
    s = ch->status;
    list_remove(&ch->elem);
    free(ch);

    //intr_set_level (old_level);
    return s;  
}
bool create(const char* file, unsigned initial_size)
{
    bool r;
    lock_acquire(&file_lock);
    r = filesys_create(file,initial_size);
    lock_release(&file_lock);
    return r;
}
bool remove(const char* file)
{
    bool r;
    lock_acquire(&file_lock);
    r = filesys_remove(file);
    lock_release(&file_lock);
    return r;
}
int open(const char* file)
{
    //file_deny_write();
    int fd;
    struct file* fp;
    lock_acquire(&file_lock);
    fp = filesys_open(file);
    lock_release(&file_lock);
    if(fp == NULL)
        return -1;
    else
    {
        struct thread* th= thread_current();
        struct file_elem* fe;
        fe = (struct file_elem*)malloc(sizeof(struct file_elem));
        fe->fp = fp;
        fe->fd = th->fd;
        th->fd += 1;
        list_push_back(&th->file_list,&fe->elem); 
     /*   
        lock_acquire(&file_lock);
        file_deny_write(fp);
        lock_release(&file_lock);
       */ 
        return fe -> fd;
    }
}
int filesize(int fd)
{
    int l;
    struct file* fp = get_file(thread_current(),fd);
    if(fp ==NULL)
        return -1;
    lock_acquire(&file_lock);
    l = file_length(fp);
    lock_release(&file_lock);

    return l;
}
int read(int fd, void *buffer, unsigned size)
{

    if(fd == 0)
    { 
        unsigned i=0;
        uint8_t* bp = (uint8_t*)buffer;
        while(i<size)
            bp[i++] = input_getc();
        return size;
    }
    else
    {
        int b;
        struct file* fp = get_file(thread_current(),fd);
        if(fp == NULL)
            return -1;
        lock_acquire(&file_lock);
        b = file_read(fp,buffer,size);
        lock_release(&file_lock);
        return b;
    }
}
int write(int fd, const void *buffer, unsigned size)
{
    if(fd == 1)
    {
        putbuf(buffer,size);
        return size;
    }
    int b;
    struct file* fp = get_file(thread_current(), fd);
    if(fp == NULL)
        return -1;
    lock_acquire(&file_lock);
    b = file_write(fp, buffer, size);
    lock_release(&file_lock);
    return b;
}
void seek(int fd, unsigned position)
{
    struct file* fp = get_file(thread_current(), fd);
        if(fp == NULL)
            return;
    lock_acquire(&file_lock);
    file_seek(fp, position);
    lock_release(&file_lock);
}
unsigned tell(int fd)
{
    unsigned d;
    struct file* fp = get_file(thread_current(), fd);
    if(fp ==NULL)
        return -1;
    lock_acquire(&file_lock);
    d=file_tell(fp);
    lock_release(&file_lock);
    return d;
}
void close(int fd)
{
    //file_allow_write();
    struct file* fp = get_file(thread_current(), fd);
    if(fp == NULL)
        return;
    lock_acquire(&file_lock);
    file_close(fp);
   // file_allow_write(fp);
    lock_release(&file_lock);
    //remove entry
    struct list l= thread_current()->file_list;
    struct list_elem *e;
    struct file_elem* f;
    for (e= list_begin(&l); e != list_end(&l); e = list_next(e))
    {
        f = list_entry(e, struct file_elem, elem);
        if(f->fd == fd)
            break;
    }
    list_remove(e);
    free(f);
}

unsigned add_trans(const void* add)
{
    if(!is_user_vaddr((const void*)add)||
            (const void*)add < 0x08048000)
        exit(-1);

    void* ptr = pagedir_get_page(thread_current()->pagedir,add);

    if(ptr == NULL)
        exit(-1);

    return (unsigned)ptr;

}
