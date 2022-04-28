#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;

  release(&ptable.lock);

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  for(int i = 0; i < 16; i++) {
    p->proc_shm[i].key = -1;
    p->proc_shm[i].va = 0;
  }
  
  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// initialize shared memory 
void shminit(){
  for(int i = 0; i < SHMMNI; i++){
    shm[i].key = -1;
    shm[i].shmid = i;
    shm[i].shmid_ds.shm_segsz = 0;
    shm[i].shmid_ds.shm_cpid = -1;
    shm[i].shmid_ds.shm_lpid = -1;
    shm[i].shmid_ds.shm_nattch = 0;
    shm[i].shmid_ds.ipc_perm.key = -1;
    shm[i].shmid_ds.ipc_perm.mode = -1;
    shm[i].shmid_ds.shminfo.shmall = SHMALL;
    shm[i].shmid_ds.shminfo.shmmax = SHMMAX;
    shm[i].shmid_ds.shminfo.shmmin = SHMMIN;
    shm[i].shmid_ds.shminfo.shmmni = SHMMNI;
    shm[i].shmid_ds.shminfo.shmseg = SHMSEG;
    for(int j = 0; j < 100; j++){
        shm[i].addr[j] = (void *)0;
    }
  }
}

// Creates a shared memory region with given key, and size depending upon flag provided
int shmget(int key, int size, int shmflg){
	if(!((shmflg == 0) && (key != IPC_PRIVATE))){
  		return -1;
  	}

	int count_req_pages = (size/PGSIZE) + 1;
  	// ENOPSC
  	if(count_req_pages > SHMALL)
  		return -1;

  	for(int i = 0; i < SHMMNI; i++){
  		// EEXIST -> shared mem exists and shmflg IPC_CREAT and IPC_EXCL
  		if(shm[i].key == key){
  			if(shmflg == (IPC_CREAT | IPC_EXCL))
  				return -1;
			// EINVAL -> shared mem exists and size is greater than size of segment
			if(shm[i].shmid_ds.shm_segsz < size)
			  return -1;

			// ENIVAL -> shared mem is to be created but size is less than SHMMIN and greater than SHMMAX
			if (size < SHMMIN || size > SHMMAX)
			  return -1;

			// permission
			int perm = shm[i].shmid_ds.shm_perm.mode;
	  		if(perm == 0666 || perm == 0444){
	  			if((shmflg == 0) && (key != IPC_PRIVATE))
	  				return shm[i].shmid;
	  			if(shmflg = IPC_CREAT)
	  				return shm[i].shmid;
	  		}
			// EACCES
	  		else
	  			return -1;
		}
  	}
  	int find_flag = 0;
  	// search for shared mem segment to be allocated
  	for(int i = 0; i < SHMMNI; i++){
  		if(shm[i].key == -1){
  			find_flag = i;
  			break;
  		}
  	}
	// ENOSPC -> all  possible shared memory IDs have been taken
  	if(find_flag == 0)
  		return -1;
  	
  	// create new segment
  	if((key == IPC_PRIVATE) || (shmflg == IPC_CREAT) || (shmflg == (IPC_CREAT | IPC_EXCL))){
  		for(int i = 0; i < count_req_pages; i++){
  			char *shmpage = kalloc();
  			if(!shmpage){
  				cprintf("Shared memory page allocation failed\n");
  				return -1;
  			}
  		} 
  		memset(shmpage, 0, PGSIZE)
  		shm[find_flag].key = key;
  		shm[find_flag].shmid = find_flag;
  		shm[find_flag].addr[i] = (void *)V2P(shmpage);
  		shm[find_flag].shmid_ds.shm_segsz = count_req_pages;
  		shm[find_flag].shmid_ds.shm_cpid = myproc()->pid;
		  shm[find_flag].shmid_ds.shm_lpid = 0;
		  shm[find_flag].shmid_ds.shm_nattch = 0;
		  shm[find_flag].shmid_ds.ipc_perm.mode = /*last significant 9 bits*/;
		  shm[find_flag].shmid_ds.ipc_perm.key = key;
	}
	return shm[find_flag].shmid;
}

// attaches shared memory segment identified by shmid to the virtual address shmaddr if provided; otherwise attach at the first fitting address
void *shmat(int shmid, void *shmaddr, int shmflg){
	// EINVAL -> an argument value is not valid, out of range, or NULL.
	if (shmid > SHMMNI || shmid < 0)
    return (void *)-1;
  int index = -1, idx, perm_flag;
  uint size = 0, seg;
  void *va = (void*)HEAPLIMIT, *min_va;
  struct proc *process = myproc();
  index = shm[shmid].shmid;
  // shmid not found
  if(index == -1){
    return (void*)-1;
  }
	// EINVAL -> the shmid parameter is not a valid shared memory identifier.
  if (shm[shmid].key == -1)
    return (void *)-1;
	// EINVAL
	if(shmflg == SHM_REMAP && shmaddr == NULL)
		return (void *)-1;
  	int perm = shm[shmid].shmid_ds.shm_perm.mode;
  	// The process must have read permission for the segment. If this flag is not specified, the segment is attached for read and write access, and the process must have read and write permission for the segment.
  	if (shmflg == SHM_RDONLY)
    		perm = 444;
	else
		perm = 666;
  	// EACCES -> the shared memory segment is to be attached in read-only mode and the calling thread does not read permission to the shared memory segment.
  	if (shm[shmid].shmid_ds.shm_perm.mode != 444 && shmflg != SHM_RDONLY)
    		return (void *)-1;
	if(shmaddr == NULL){
		// choose page-aligned address to attch segment
	}
	else if(shmaddr != NULL && shmflg == SHM_RND){
		// attch at address equal to shmaddr rounded down to the nearest multiple of SHMLBA
	}
	else{
		// page-aligned address at which attch occurs
	}

	// ENOMEM -> function needed to allocate storage, but no storage is available.
  // memory allocation code hre
  // if (!check)
  //   return -1;

  idx = -1;
  for(int i = 0, i < SHMALL, i++){
    if(process->pages[i].key != -1){
      idx = i;
      break;
    }
  }
  if(index != -1){
    process->pages[idx].shmid = shmid;
    process->pages[idx].virtual_addr = va;
    process->pages[idx].key = shm[index].key;
    process->pages[idx].size = shm[index].size;
    process->pages[idx].perm = perm_flag; 
    shm[index].shmid_ds_buffer.shm_nattch =+ 1;
    shm[index].shmid_ds_buffer.shm_lpid = process->pid;
  }else{
    return -1;
  }
  return va;
}

int shmdt(void *shmaddr){
  char *shmaddr;
  if (argptr(0, &shmaddr, sizeof(*shmaddr)) < 0)
    return -1;
  struct proc *process = myproc();
  void *va = (void *)0;
  int shmid, index, i, flag1 = -1;
  uint size;
  int flag1 = -1;
  for(i = 0; i < SHMALL; i++){
    if (process->proc_shm[i].va != shmaddr)
      continue;
    if (process->proc_shm[i].va == shmaddr){
      flag1 = i;
      break;
    }
  }
  // EINVAL -> limit for number of shared memory segments for that process reached
  if (flag1 == -1)
    return -1;
  int shmid = process->proc_shm[flag1].shmid;
  // EINVAL -> The value of shmaddr is not the start address of a shared memory segment.
  if (shm[shmid].key == -1)
    return -1;
  if (shm[shmid].shmid_ds.shm_perm.rem == 1 && shm[shmid].shmid_ds.shm_nattch == 0)
  {
    // if nattch becomes zero and segment is marked for deletion, it is deleted
  }
  // find the index from pages array which is attached at the provided shmaddr.
  for(i = 0; i < SHMALL; i++){
    if(process->pages[i].key != -1 && process->pages[i].virtual_addr == shmaddr){
      va = process->pages[i].virtual_addr;
      index = i;
      shmid = process->pages[i].shmid;
      size = process->pages[index].size;
      break;
    }
  }
  if(va){
    process->pages[index].shmid = -1;
    process->pages[index].key = -1;
    process->pages[index].size = 0;
    process->pages[index].virtual_addr = (void *)0;
    // decrement attaches
    if(shm[shmid].shmid_ds_buffer.shm_nattch > 0){
      shm[shmid].shmid_ds_buffer.shm_nattch -= 1;
    }
    // remove the segments
    if(shm[shmid].shmid_ds_buffer.shm_nattch == 0){
      for(i = 0; i < shm[index].size; i++){
        char *addr = (char *)P2V(shm[index].physical+addr[i]);
        kfree(addr);
        shm[index].physical_addr[i] = (void *)0;
      }
      shm[shmid].size = 0;
      shm[shmid].key = shm[shmid].shmid = -1;
      shm[shmid].shmid_ds.shm_nattch = 0;
      shm[shmid].shmid_ds.shm_segsz = -1;
      shm[shmid].shmid_ds.shm_perm.key = -1;
      shm[shmid].shmid_ds.shm_perm.mode = -1;
      shm[shmid].shmid_ds.shm_perm.rem = 0;
      shm[shmid].shmid_ds.shm_cpid = -1;
      shm[shmid].shmid_ds.shm_lpid = -1;
    }
    shm[shmid].shmid_ds_buffer.shm_lpid = process->pid;
  }
  return 0;
}

int shmctl(int shmid, int cmd, void *buf){
	struct shmid_ds *shmid_ds_buffer = (struct shmid_ds *)buf;
	// EINVAL -> shmid not a valid identifier
	if(shmid < 0 || shmid > SHMMNI || shm[shmid].key == -1)
		return -1;

	// EINVAL -> cmd is not valid command
	if((cmd == IPC_STAT || cmd == IPC_SET || cmd == IPC_INFO || cmd == IPC_RMID))
		return -1;
	int perm = shm[i].shmid_ds.shm_perm.mode;
	if(cmd == IPC_STAT){
		// RW also considered bacause RW has read permission
		if(perm == 0444 || perm == 0666){
			// copy information from kernel data stucture to shmid_ds pointed by buf
			shmid_ds_buffer->shm_segsz = shm[shmid].shmid_ds.shm_segsz;
			shmid_ds_buffer->shm_cpid = shm[shmid].shmid_ds.shm_cpid;
			shmid_ds_buffer->shm_lpid = shm[shmid].shmid_ds.shm_lpid;
			shmid_ds_buffer->shm_nattch = shm[shmid].shmid_ds.shm_nattch;
			shmid_ds_buffer->shm_perm.perm_key = shm[shmid].shmid_ds.shm_perm.perm_key;
			shmid_ds_buffer->shm_perm.perm_mode = shm[shmid].shmid_ds.shm_perm.mode;
			return 0;
		}
	       // EACCES -> does not allow read access for shmid
		else{
			return -1; 
		}
		// EFAULT -> address pointed to by buf isn't accessible
		//
	}
	if(cmd == IPC_SET){
		// EFAULT -> address pointed to by buf isn't accessible
		//

		// creator permission
		else if(perm == 666){
			// 9 bits user mode
	                // write to kernel data strcuture
        	        //shm[shmid].shmid_ds = *buf;
                	shm[shmid].shmid_ds.shm_perm.mode = shmid_ds_buffer->shm_perm.perm_mode;
                	shm[shmid].shmid_ds.shm_segsz = shmid_ds_buffer->shm_segsz;
                	shm[shmid].shmid_ds.shm_cpid = shmid_ds_buffer->shm_cpid;
               		shm[shmid].shmid_ds.shm_lpid = shmid_ds_buffer->shm_lpid;
                	shm[shmid].shmid_ds.shm_nattch = shmid_ds_buffer->shm_nattch;
                	shm[shmid].shmid_ds.shm_perm.perm_key = shmid_ds_buffer->shm_perm.perm_key;
                	shm[shmid].shmid_ds.shm_perm.mode = shmid_ds_buffer->shm_perm.perm_mode;
			return 0;
		}
		// EPERM 
		else
			return -1;
		
	}
	if(cmd == IPC_RMID){
		if(perm == 0666){
			// Mark segment to be destroyed
			int page_count = (size / PGSIZE) + 1;
			if(shm[shmid].shmid_ds,shm_nattch == 0){
				////////
				return 0; 
			}
			else{
				// mark for deleting
				return 0;
			}
		}
		// EPERM 
		else
			return -1;
	}
	if(cmd == IPC_INFO){
		shmid_ds_buffer->shminfo.shmall = shm[shmid].shmid_ds.shminfo.shmall;
		shmid_ds_buffer->shminfo.shmmax = shm[shmid].shmid_ds.shminfo.shmmax;
		shmid_ds_buffer->shminfo.shmmin = shm[shmid].shmid_ds.shminfo.shmmin;
		shmid_ds_buffer->shminfo.shmmni = shm[shmid].shmid_ds.shminfo.shmmni;
		shmid_ds_buffer->shminfo.shmseg = shm[shmid].shmid_ds.shminfo.shmseg;
		return 0;
	}
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}
