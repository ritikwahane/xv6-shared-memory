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
  int flag;
  if(argint(0, &key) < 0)
    return -1;
  if(argint(1, &size) < 0)
    return -1;
  if(argint(2, &flag) < 0)
    return -1;
  for(int i = 0; i < SHMMNI; i++){  
    // EEXIST -> shared mem exists and shmflg IPC_CREAT and IPC_EXCL
	if(shm[i].key == key && (flag == (IPC_CREAT|IPC_EXCL|0666) || flag == (IPC_CREAT|IPC_EXCL|0444)))
      		return -1;
    	
	// EINVAL -> shared mem exists and size is greater than size of segment  
	if(shm[i].key == key && shm[i].shmid_ds.shm_segsz < size) 
      		return -1;

	// key exists and segment size less than size of segment
	if(shm[i].key == key && shm[i].shmid_ds.shm_segsz >= size)
		return shm[i].shmid;

	// ENIVAL -> shared mem is to be created but size is less than SHMMIN and greater than SHMMAX 
	if(shm[i].key != key && (size < SHMMIN || size > SHMMAX))
		return -1;
	
	// ENOENT -> no segment exists for the key and IPC_CREAT not speicfied 
	if(shm[i].key != key && flag != IPC_CREAT)
		return -1;
	
	// EACCESS 
	if(flag == (IPC_CREAT|IPC_EXCL|0444) || flag == (IPC_CREAT|0444))
		return -1;	
  }
  // ENOSPC 
  //if(current _shared_mem_size + size > SHMALL)
	// return -1;

	// IPC_PRIVATE key create new shared mem	
	if(shm[i].key == IPC_PRIVATE || flag == (IPC_CREAT|IPC_EXCL|0666) || flag == (IPC_CREAT|IPC_EXCL|0444) || flag == (IPC_CREAT|0666) || flag == (IPC_CREAT|0444))
		//shmget();
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
