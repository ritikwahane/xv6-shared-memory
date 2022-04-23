#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int sys_shmget(void){
  int key;
  int size;
  int shmflg;
  if(argint(0, &key) < 0)
    return -1;
  if(argint(1, &size) < 0)
    return -1;
  if(argint(2, &shmflg) < 0)
    return -1;
	return shmget(key, size, shmflg);
}

void *sys_shmat(void)
{
  int shmid;
  char *shmaddr;
  int flag;
  if (argint(0, &shmid) < 0)
    return -1;
  if (argptr(1, &shmaddr, sizeof(*shmaddr)) < 0)
    return -1;
  if (argint(2, &flag) < 0)
    return -1;
  // EINVAL -> an argument value is not valid, out of range, or NULL.
  if (shmid > SHMMNI || shmid < 0)
    return -1;
  // EINVAL -> the shmid parameter is not a valid shared memory identifier.
  if (shm[shmid].key == -1)
    return -1;
  int permissions = shm[shmid].shmid_ds.shm_perm.mode;
  // The process must have read permission for the segment. If this flag is not specified, the segment is attached for read and write access, and the process must have read and write permission for the segment.
  if (flag == SHM_RDONLY)
    permissions = 444;
  // EACCESS -> the shared memory segment is to be attached in read-only mode and the calling thread does not read permission to the shared memory segment.
  if (shm[shmid].shmid_ds.shm_perm.mode == 444 && flag != SHM_RDONLY)
    return -1;
  // limit for number of shared memory segments for that process reached
  if (flag1 == -1)
    return -1;
  // ENOMEM -> function needed to allocate storage, but no storage is available.
  if (!check) // ENOMEM
    return -1;
}

int sys_shmdt(void)
{
  char *shmaddr;
  if (argptr(0, &shmaddr, sizeof(*shmaddr)) < 0)
    return -1;
  struct proc *curproc = myproc();
  int flag1 = -1;
  for (int i = 0; i < 16; i++)
  {
    if (curproc->proc_shm[i].va != shmaddr)
      continue;
    if (curproc->proc_shm[i].va == shmaddr)
    {
      flag1 = i;
      break;
    }
  }
  // EINVAL -> limit for number of shared memory segments for that process reached
  if (flag1 == -1)
    return -1;
  int shmid = curproc->proc_shm[flag1].shmid;
  // EINVAL -> The value of shmaddr is not the start address of a shared memory segment.
  if (shm[shmid].key == -1)
    return -1;
  if (shm[shmid].shmid_ds.shm_perm.rem == 1 && shm[shmid].shmid_ds.shm_nattch == 0)
  {
    // if nattch becomes zero and segment is marked for deletion, it is deleted
  }
  return 0;
}

int sys_shmctl(void){
  int shmid, cmd;
  struct shmid_ds *buf;
  if (argint(0, &shmid) < 0)
    return -1;
  if (argint(1, &cmd) < 0)
    return -1;
  if (argptr(2, (void *)&buf, sizeof(*buf)) < 0)
    return -1;
	return shmctl(shmid, cmd, (void *)buf);
}

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}
