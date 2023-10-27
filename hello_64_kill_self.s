# kernel 
# https://github.com/torvalds/linux/blob/master/arch/x86/entry/entry_64.S
# https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
#
# Searchable Linux Syscall Table for x86 and x86_64
# https://filippo.io/linux-syscall-table/


# x86-64 Linux System Call convention
# https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf
# A.2 AMD64 Linux Kernel Conventions
#
# A system-call is done via the syscall instruction.
# The number of the syscall has to be passed in register %rax.
# The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.
# The kernel destroys registers %rcx and %r11.
 

.section .text
.global _start

_start:
    # write message
    mov $1, %rax          # syscall sys_write
    mov %rax, %rdi        # file descriptor 1 (stdout)
    mov $msg, %rsi        # pointer to the message
    mov $len, %rdx        # length
    syscall

    # get pid
    mov $39, %rax          # syscall sys_getpid
    syscall

    # kill self
    mov %rax, %rdi         # save PID -> 1st parameter
    mov $62, %rax          # syscall sys_kill
    mov $9, %rsi           # SIGKILL
    syscall

.section .data
msg:
    .string "Hello world!\n"
len = . - msg
