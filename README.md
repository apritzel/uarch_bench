 uarch_bench
=============

Quick start
-----------

For the impatient:

	$ make
	$ ./insthru -a

./insthru -h gives help output.

Overview
--------

uarch_bench is measuring instruction throughput on a CPU. It can calculate
the IPC (instruction per cycle) ratio of many instructions by executing
those instructions in a rolled-out loop and measuring the number of
CPU cycles needed.

How it works
------------

The code first populates a memory page with assembly instructions in a loop.
The number of each instruction and the loop counter can be tuned on the
commandline, but will default to sensible values.
The instruction sequence is chosen to not create unnecessary dependencies,
so the full pipeline of the CPU should be utilized.
It will then prepare the CPU's performance counters (using the Linux
perf framework) and will execute this code. It records the number of CPU
cycles as well as the number of executed instructions. The branch to the
beginning of the loop is contained in those numbers, but the loop size
it rather large, so the effect should be minimal. There are no
means taken to reduce the numbers by some values to account for the loop
instruction, if you have a decent idea of what to subtract, you are welcome
to do this yourself (you can see the absolute numbers if you wish).
By dividing those numbers it calculates an maximum IPC for that instruction.
The sequence is deliberately chosen to keep as many execution
units busy as possible, so the value is more of an upper boundary. Real life
code will probably never reach that value, as other instructions, control
flow, memory accesses and interrupts or traps will spoil the run.
The idea is to detect how many execution units in the CPU are able to
execute that instruction. It can be used to do some microarchitectural
fingerprinting, where certain CPUs will show a characteristic pattern.
