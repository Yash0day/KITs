#include<linux/init.h>
#include<linux/module.h>
#include<linux/syscalls.h>
#include<linux/kallsyms.h>
#include<linux/slab.h>
#include<asm/unistd.h>
#include<linux/gfp.h>
#include<linux/kern_levels.h>
#include<asm/paravirt.h>

unsigned long **SYS_CALL_TABLE;

unsigned long cr0;
extern unsigned long __force_order;

static inline void write_forced_cr0(unsigned long val){
	asm volatile("mov %0,%%cr0":"+r" (val),"+m"(__force_order));
}

static inline void EnablePageWriting(void){ //write_cr0(0) //
	write_forced_cr0(read_cr0() & (~0x10000));
}


static inline void DisablePageWriting(void){ /*write_cr0(1) */
	write_forced_cr0(read_cr0() | 0x10000);
}

//Initialization of original function
asmlinkage int (*original_open)(int dirfd, const char *pathname, int flags); 

asmlinkage int HookOpen(int dirfd, const char *pathname, int flags) {
	
	char letter; 
	int i=0;

	char directory[255];
	char ourfile[16] = "output01";


	while (letter != 0 || i<6){
		get_user(letter, pathname+i);
		directory[i] = letter;
		i++;
	}
	if(strcmp(ourfile, directory) == 0){
		printk(KERN_INFO "FILE ACCESSED!!! %s", directory);
	}
	memset(directory, 0, 255);

	return (*original_open)(dirfd, pathname, flags);
	
}

static int __init SetHooks(void){
	/*access Syscall Table*/
	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table");

	printk(KERN_INFO "HOOKS Will be Set\n");
	printk(KERN_INFO "SYSTEM CALL TABLE at %p\n", SYS_CALL_TABLE);
	
	cr0 = read_cr0();
	EnablePageWriting();
	printk(KERN_INFO ">>Page writing enabled>>>>>>>>>");

	/*Replace pointer of Syscall_read by our Syscall*/
	original_open = (void*)SYS_CALL_TABLE[__NR_openat];
	SYS_CALL_TABLE[__NR_openat] = (unsigned long*)HookOpen;
	
	cr0 = read_cr0();
	DisablePageWriting();
	printk(KERN_INFO "Page writing disabled<><><><><");

	return 0;
}

static void __exit HookCleanup(void){

	/*Clean up our Hook*/
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_openat] = (unsigned long*)original_open;
	DisablePageWriting();

	printk(KERN_INFO "HooksCleaned Up! ");
}

module_init(SetHooks);
module_exit(HookCleanup);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Rooter");
MODULE_DESCRIPTION("Simple Hooking of a OPEN Syscall");
MODULE_VERSION("1.0");
