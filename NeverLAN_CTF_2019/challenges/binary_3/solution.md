# Instructions
Another day, another disgruntled engineer. It seems that the login is working fine, but some portions of the application are broken. Do you think you could fix the the code and retrieve the flag?

# Solution

## Gathering Information
To see what we are working with, let us use the `file` command on the binary executable.
This yields the output:
```
./get_flag: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9d6e0012cc1b18b155cb8f490eb1fbed910694e2, not stripped
```

From this output, we note that the binary is not stripped.
This means the binary contains symbols in it, which can be used to gain useful information such as which functions are used.

## Finding the Functions
To solve this challenge, we will use the [angr](https://github.com/angr) binary analysis framework.

We start by inspecting which functions are called within the binary.
To do this, we use the Python script [script1.py](https://github.com/Live10NOP/CTF_Writeups/blob/master/NeverLAN_CTF_2019/challenges/binary_3/scripts/script1.py).

This script does the following
1. We create a project from the binary executable we are analyzing:<br>
`proj = angr.Project("./get_flag", auto_load_libs=False)`
1. We find the .text section of the binary, where we expect the functions to be located:<br>
`text_section = main_object.find_section_containing(main_object.entry)`
1. We create a control flow graph (CFG) of the .text section. Since we saw the binary is not stripped we can use its symbols as a starting point to find functions.<br>
`cfg = proj.analyses.CFGFast(symbols=True, regions=[(text_sec_min_addr, text_sec_max_addr)])`
1. Next, we simply print the name and address of each function that was discovered in the binary.

We observe the following interesting functions:
```
u @ (0x400dca)
b @ (0x400e42)
c @ (0x400eb7)
f @ (0x40104a)
l @ (0x4013af)
a @ (0x401714)
g @ (0x401a79)
s @ (0x401dde)
x @ (0x402143)
d @ (0x4022a6)
```

## Drawing the Call Graphs
Next, let us see if we can obtain a better understanding of how these functions relate to each other.
We wish to know which functions call which and what library functions are called in each.
We use [script2.py](https://github.com/Live10NOP/CTF_Writeups/blob/master/NeverLAN_CTF_2019/challenges/binary_3/scripts/script2.py).

Note that we no longer restrict out CFG generation to the .text section, since we are also interested in which library functions are called by the functions.
In this script, we start at the main function and perform a depth-first search over every function that is called from within another.
We obtain the following output:
```
main @ (0x4024bc) ->
	c @ (0x400eb7)
	u @ (0x400dca)
	puts @ (0x400b90)
	b @ (0x400e42)
	puts @ (0x400b90)
	puts @ (0x400b90)
b @ (0x400e42) ->
	printf @ (0x400bd0)
	fgets @ (0x400c10)
	strtok @ (0x400c60)
	strcmp @ (0x400c20)
u @ (0x400dca) ->
	printf @ (0x400bd0)
	fgets @ (0x400c10)
	strtok @ (0x400c60)
	strcmp @ (0x400c20)
c @ (0x400eb7) ->
	strcpy @ (0x400b80)
	strcat @ (0x400c70)
	# --- 8< --- (strcat @ (0x400c70) x 15)
	strcat @ (0x400c70)
```

Comparing this output to the functions we saw in the previous section, we notice that not all of the defined functions are being called (this is also hinted in the instructions).

Let us try to find out how the unreachable functions relate to each other.
We do this by searching for any nodes in our CFG that have no incoming edges.
Any of the discovered functions that is not called itself, but which calls other functions, will be a good point to continue our investigation from.

We use [script3.py](https://github.com/Live10NOP/CTF_Writeups/blob/master/NeverLAN_CTF_2019/challenges/binary_3/scripts/script3.py) to find functions that are not called themselves.

This script shows us that the function `d` that we discovered is not called in the binary.
Let us draw the call graph again, but this time we start at function `d`, instead of `main`, [script4.py](https://github.com/Live10NOP/CTF_Writeups/blob/master/NeverLAN_CTF_2019/challenges/binary_3/scripts/script4.py)

We get the following output:
```
d @ (0x4022a6) ->
	x @ (0x402143)
	malloc @ (0x400c50)
	sprintf @ (0x400c80)
	printf @ (0x400bd0)
	socket @ (0x400ca0)
	gethostbyname @ (0x400c30)
	memset @ (0x400be0)
	htons @ (0x400bc0)
	memcpy @ (0x400c40)
	connect @ (0x400c90)
	strlen @ (0x400bb0)
	write @ (0x400ba0)
	write @ (0x400ba0)
	memset @ (0x400be0)
	read @ (0x400c00)
	read @ (0x400c00)
	close @ (0x400bf0)
	puts @ (0x400b90)
	free @ (0x400b70)
x @ (0x402143) ->
	f @ (0x40104a)
	strcat @ (0x400c70)
	l @ (0x4013af)
	strcat @ (0x400c70)
	a @ (0x401714)
	strcat @ (0x400c70)
	g @ (0x401a79)
	strcat @ (0x400c70)
	s @ (0x401dde)
	strcat @ (0x400c70)
s @ (0x401dde) ->
g @ (0x401a79) ->
a @ (0x401714) ->
l @ (0x4013af) ->
f @ (0x40104a) ->
```

It seems as if function `d` tries to open a connection to a remote host.

## Symbolically Executing the Function
To determine what function `d` does, we will execute it symbolically.
We use [script5.py](https://github.com/Live10NOP/CTF_Writeups/blob/master/NeverLAN_CTF_2019/challenges/binary_3/scripts/script5.py).

We will hook into the functions `printf` and `gethostbyname` using angr's [SimProcedures](https://docs.angr.io/extending-angr/simprocedures) to print out what data is being passed to them.
Next, we set up a call state for function `d` and create a [simulation manager](https://docs.angr.io/core-concepts/pathgroups) to start at this state.
Finally, we run the simulation manager.

The hooks we created print out the following strings:
```
printf called with arg: b'GET /81c26d1dd57fd11842fc13e53540db80/eacbe4d1b2dee530eee7460477877c4d/667d5fa72f80788a5ed2373586e57ff6/c4ff45bb1fab99f9164b7fec14b2292a/6470e394cbf6dab6a91682cc8585059b HTTP/1.0\r\n\r\n'
gethostbyname called with arg: b'www.gr3yR0n1n.com'
```

This clearly shows us we need to visit the URL:
```
www.gr3yR0n1n.com/81c26d1dd57fd11842fc13e53540db80/eacbe4d1b2dee530eee7460477877c4d/667d5fa72f80788a5ed2373586e57ff6/c4ff45bb1fab99f9164b7fec14b2292a/6470e394cbf6dab6a91682cc8585059b
```

# Flag
Visiting this URL gives us the flag:
```
flag{AP1S_SH0ULD_4LWAYS_B3_PR0T3CTED}
```
