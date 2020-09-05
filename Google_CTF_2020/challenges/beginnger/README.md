# Goal
We have a challenge binary executable named `a.out`.
We have to find the flag by finding the correct input to provide this binary.

# Solution
## Information Gathering
First, we run `a.out` and receive the following prompt:
```Bash
$ ./a.out 
Flag:
```
So, we know the challenge expects us to enter the flag via standard input.

When start by analyzing `a.out` in radare2.
The following image shows the disassembled machine code of the main function.

At instruction `0x000010a9` we see a call to `scanf`.
This is where the binary reads in the input.
At instruction `0x000010a2` the first parameter to scanf, the format string, is prepared.
We can see the format string given to `scanf` is "%15s".
This means that 15 characters will be read from input and we can therefore assume the flag will have length 15.
Also, from the instruction at `0x0000109a` we can see that `scanf` will store the input at the address contained in the `rbp` register.

At instruction `0x0000111d` the binary prints out "SUCCESS".
We can assume that this point is reached if the user enters the correct input.
At this point the address where the input is stored is still in the `rbp` register (note that `rbp` remains unchanged after `0x0000109a`).
Therefore, we want to print out this memory when the program reaches this instruction, which will reveal the flag.
We use `angr` to this end.

## Solving the Flag with angr
We start by creating a project, a state and a simulation manager.
```Python
proj = angr.Project('a.out', auto_load_libs=False)
start_state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(start_state)
```
We will use this simulation manager to perform symbolic analysis on the target executable.
This will execute all the branches in the program simultaneously, while placing constraints on the memory and registers that correspond to each specific branch.
This is useful, because if we reach the "SUCCESS" point in the program, we have a set of constraints for the memory containing the input.
We can solve these constraints to obtain the correct input.

First, we tell angr what program point to search for.
Once this point has been reached, we extract the program state (note that angr uses a base address of `0x400000`, so we have to add this to `0x0000111d` when specifying the success state).
```Python
simgr.explore(find=0x40111d)
assert len(simgr.found) > 0, "Could not find success state."
found_state = simgr.found[0]
```
From this state, we extract 15 bytes of memory stored at the address in the `rbp` register.
```Python
symbolic_chars = [found_state.mem[found_state.regs.rbp + i].char.resolved for i in range(15)]
```
Since these bytes correspond to user input, they will be symbolic (as opposed to concrete), because user input can take on any value.
However, as we have reached the success state, these symbolic bytes will be constrained to values that are legal in this program state.
We want to evaluate these symbolic characters, with respect to the constraints, in order to obtain input that will allow us to reach the success state.
First, we concanate the symbolic characters together, so that we can solve them as a group.
```Python
symbolic_flag = claripy.Concat(*symbolic_chars)
```
Then, we use the theorem prover attached to the found state to solve the constraints placed on the symbolic flag to obtain a concrete flag.
```Python
concrete_flag = found_state.solver.eval(symbolic_flag, cast_to=bytes)
flag = concrete_flag.decode('ascii')
```
This concrete flag corresponds to input that will lead `a.out` to the success state.
However, it looks weird:
```
CTF{\x00\xc8M\x00f0\xcf\x00\x00!}
```
This is clearly not the flag, as we cannot enter it to `./a.out` (because of the null bytes).
We need to add additional constraints to the symbolic characters in order to ensure that only non-null bytes are included in the concrete flag.
We add these constraints after creating the symbolic characters:
```Python
for sym_char in symbolic_chars:
        found_state.add_constraints(sym_char != 0)
```

This time, we obtain the correct flag: `CTF{S1MDf0rM3!}`
We confirm this by providing it to `./a.out` as input:
```Bash
$ echo 'CTF{S1MDf0rM3!}' | ./a.out 
Flag: SUCCESS
```
