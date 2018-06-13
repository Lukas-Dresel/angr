import angr
import claripy

proj = angr.Project('/bin/ls')
s = proj.factory.blank_state()
loaded = s.memory.load(claripy.BVS('addr', 64) + 10, 8)
