# CaveCarver

Code cave is a technique used to inject additional code or shellcode into an executable
without affecting the original functionality of the program.
Our Project instruments code cave by adding an additional Section to the PE file 
where the shellcode resides in. After patching the PEs EntryPoint the control flow gets redirected to the shellcode.

