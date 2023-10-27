# Sample code for playing with assembler and syscalls in Linux

## hello_64.s 
Simplest form. Uses GNU AT&T syntax.

```
# Compile the assembly code in hello_64.s into an object file (hello_64.obj)
as hello_64.s -o hello_64.obj

# Link the object file (hello_64.obj) to create an executable (hello_64)
ld hello_64.obj -o hello_64

# Remove the intermediate object file to clean up the working directory
rm hello_64.obj

# Disassemble the executable (hello_64) and display its assembly code
objdump -d hello_64

# Display detailed information about the executable using readelf
readelf -a hello_64

# Execute the 'hello_64' program located in the current directory
./hello_64

# Run the 'hello_64' program with strace (system call tracer) and save the output to 'trace.txt'
sudo strace -o trace.txt ./hello_64

# Display the contents of the 'trace.txt' file, which contains the system call trace generated by strace
cat trace.txt
```


## hello_64_kill_self.s 
Some modifications, kills self instead of clean exit. Uses GNU AT&T syntax.

```
# Compile the assembly code in hello_64__kill_self.s into an object file (hello_64_kill_self.obj), folding the data section into the text section (-R)
as hello_64_kill_self.s -o hello_64_kill_self.obj -R

# Link the object file 'hello_64_kill_self.obj' to create an executable 'hello_64_kill_self', removing all symbol information.
ld hello_64_kill_self.obj -o hello_64_kill_self --strip-all

# Remove the intermediate object file to clean up the working directory
rm hello_64_kill_self.obj

# Disassemble the executable (hello_64_kill_self) and display its assembly code
objdump -d hello_64_kill_self

# Display detailed information about the executable using readelf
readelf -a hello_64_kill_self

# Execute the 'hello_64_kill_self' program located in the current directory
./hello_64_kill_self

# Run the 'hello_64_kill_self' program with strace (system call tracer) and save the output to 'trace.txt'
sudo strace -o trace.txt ./hello_64_kill_self

# Display the contents of the 'trace.txt' file, which contains the system call trace generated by strace
cat trace.txt
```

# AT&T syntax vs Intel syntax

AT&T syntax and Intel syntax are two different assembly language syntaxes used for writing low-level code that can be directly understood by a computer's processor. These syntaxes differ in their notation and conventions for representing assembly instructions and operands. Here's an overview of the key differences between AT&T syntax and Intel syntax:

**AT&T Syntax:**

1. **Operand Order**: In AT&T syntax, the source operand comes before the destination operand when specifying instructions. For example, to move the value in register `eax` into `ebx`, you would write it as:
   ```
   movl %eax, %ebx
   ```

2. **Registers**: Registers are prefixed with a percent sign (`%`) in AT&T syntax. For example, `%eax` represents the `eax` register.

3. **Immediate Values**: Immediate values (constants) are prefixed with a dollar sign (`$`) in AT&T syntax. For instance, `movl $42, %eax` would load the value 42 into the `eax` register.

4. **Memory Addresses**: Memory addresses typically use a format like `disp(base, index, scale)`. This is used when addressing memory in more complex ways, such as for indexed addressing. For example, `(%ebx,%esi,4)` means an address computed as `base + index * scale`, which is commonly used in array indexing.

5. **Size Suffixes**: Instructions are often suffixed with size indicators, such as `b` (byte), `w` (word), `l` (long), or `q` (quadword) to indicate the size of data being operated on. For example, `movl` is used for moving long (4-byte) values.

**Intel Syntax:**

1. **Operand Order**: In Intel syntax, the destination operand comes before the source operand. For the same operation mentioned earlier, you would write it as:
   ```
   mov ebx, eax
   ```

2. **Registers**: Registers are referred to by their names directly, without any special prefixes. For example, `eax` represents the `eax` register.

3. **Immediate Values**: Immediate values don't require a special prefix in Intel syntax. You can simply write the constant, like `mov eax, 42`.

4. **Memory Addresses**: Memory addresses are specified using square brackets, such as `[eax]` to access the memory at the address stored in the `eax` register.

5. **Size Indicators**: The size of data being operated on is often implicit in Intel syntax. The assembler determines the size based on the specific operation. For example, `mov` alone might imply a move of a 4-byte (long) value.

Compare the two outputs from:
```
# Display information about the 'hello_64' executable using objdump with default options.
objdump hello_64
```

```
hello_64:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 c7 c0 01 00 00 00    mov    $0x1,%rax
  401007:       48 c7 c7 01 00 00 00    mov    $0x1,%rdi
  40100e:       48 c7 c6 00 20 40 00    mov    $0x402000,%rsi
  401015:       48 c7 c2 0e 00 00 00    mov    $0xe,%rdx
  40101c:       0f 05                   syscall
  40101e:       48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
  401025:       48 31 ff                xor    %rdi,%rdi
  401028:       0f 05                   syscall
```

```
# Disassemble the 'hello_64' executable in Intel syntax objdump -d -Mintel hello_64
```
```
hello_64:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 c7 c0 01 00 00 00    mov    rax,0x1
  401007:       48 c7 c7 01 00 00 00    mov    rdi,0x1
  40100e:       48 c7 c6 00 20 40 00    mov    rsi,0x402000
  401015:       48 c7 c2 0e 00 00 00    mov    rdx,0xe
  40101c:       0f 05                   syscall
  40101e:       48 c7 c0 3c 00 00 00    mov    rax,0x3c
  401025:       48 31 ff                xor    rdi,rdi
  401028:       0f 05                   syscall
```
  
You can use Intel syntax in the AS assembler by using `.intel_syntax` directive.

NASM uses Intel syntax, which is more common for x86 assembly language. Intel syntax is often considered more straightforward and easier to read for beginners.
