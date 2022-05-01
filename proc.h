#define SHMALL 16384 
#define SHMMAX 8192
#define SHMMIN 1
#define SHMMNI 1024
#define SHMSEG 16
#define IPC_CREAT 10000000000
#define IPC_PRIVATE 1
#define IPC_EXCL 20000000000
#define IPC_STAT 30000000000
#define IPC_SET 40000000000
#define IPC_INFO 50000000000
#define IPC_RMID 60000000000
#define SHM_REMAP 70000000000
#define SHM_RDONLY 80000000000
#define SHM_RND 90000000000
#define SHMLBA PGSIZE

// Per-CPU state
struct cpu {
  uchar apicid;                // Local APIC ID
  struct context *scheduler;   // swtch() here to enter scheduler
  struct taskstate ts;         // Used by x86 to find stack for interrupt
  struct segdesc gdt[NSEGS];   // x86 global descriptor table
  volatile uint started;       // Has the CPU started?
  int ncli;                    // Depth of pushcli nesting.
  int intena;                  // Were interrupts enabled before pushcli?
  struct proc *proc;           // The process running on this cpu or null
};

extern struct cpu cpus[NCPU];
extern int ncpu;

//PAGEBREAK: 17
// Saved registers for kernel context switches.
// Don't need to save all the segment registers (%cs, etc),
// because they are constant across kernel contexts.
// Don't need to save %eax, %ecx, %edx, because the
// x86 convention is that the caller has saved them.
// Contexts are stored at the bottom of the stack they
// describe; the stack pointer is the address of the context.
// The layout of the context matches the layout of the stack in swtch.S
// at the "Switch stacks" comment. Switch doesn't save eip explicitly,
// but it is on the stack and allocproc() manipulates it.
struct context {
  uint edi;
  uint esi;
  uint ebx;
  uint ebp;
  uint eip;
};

enum procstate { UNUSED, EMBRYO, SLEEPING, RUNNABLE, RUNNING, ZOMBIE };

struct shmid_ds{
  struct ipc_perm shm_perm; //Ownership and permissions
  int shm_segsz; //Size of segment (bytes)
  int shm_cpid;  //PID of creator
  int shm_lpid;  //PID of last shmat()/shmdt()
  int shm_nattch;  //No. of current attaches
  struct shminfo shminfo;
};

struct ipc_perm{
	int perm_key;
	unsigned short mode;
};

//IPC_INFO
struct shminfo{
	unsigned long shmall;
	unsigned long shmmax;
	unsigned long shmmin;
	unsigned long shmmni;
	unsigned long shmseg;
};

struct shm{
  int key;
  int shmid;
  int size;
  int mark_delete;
  char *addr[100];
  struct shmid_ds shmid_ds;
}shm[SHMMNI];

// shared page
struct shm_shared_page{
  int key, size;
  void *va;
}shm_shared_page;

// Per-process state
struct proc {
  uint sz;                     // Size of process memory (bytes)
  pde_t* pgdir;                // Page table
  char *kstack;                // Bottom of kernel stack for this process
  enum procstate state;        // Process state
  int pid;                     // Process ID
  struct proc *parent;         // Parent process
  struct trapframe *tf;        // Trap frame for current syscall
  struct context *context;     // swtch() here to run process
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
  int shmsz:                   // Current size of shared memory
  struct shm_shared_page shm_page[16]; // Pages shared by process
};

// Process memory is laid out contiguously, low addresses first:
//   text
//   original data and bss
//   fixed-size stack
//   expandable heap
