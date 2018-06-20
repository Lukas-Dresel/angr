from mmap import PROT_WRITE, PROT_READ

import claripy
from angr.errors import SimSegfaultError
from angr.state_plugins import SimActionConstraint, sim_options, SimActionExit
from angr.utils.strings import try_load_as_string, load_expected_string

NEXT_STRING_ALLOC_STATE_GLOBALS_KEY = 'next_string_alloc_addr'

def get_next_string_alloc_addr(state, string_memory_base=0xdead0000):
    if state is None or NEXT_STRING_ALLOC_STATE_GLOBALS_KEY not in state.globals:
        return string_memory_base
    return state.globals[NEXT_STRING_ALLOC_STATE_GLOBALS_KEY]

def set_next_string_alloc_addr(state, x):
    state.globals[NEXT_STRING_ALLOC_STATE_GLOBALS_KEY] = x

def alloc_string_memory(state, length, **kwargs):
    ptr = get_next_string_alloc_addr(state, **kwargs)
    try:
        state.memory.store(ptr, claripy.BVV(0, (length + 1) * 8))
    except SimSegfaultError as ex:
        # raise
        # import ipdb; ipdb.set_trace()
        state.memory.map_region(ptr, length, PROT_READ | PROT_WRITE, init_zero=True)

    set_next_string_alloc_addr(state, ptr + (length + 1))
    return ptr

class StringSimProcedureMixin(object):
    def __init__(self, *args, **kwargs):
        self.string_memory_base = kwargs.pop('string_memory_base', 0xdead0000)
        self.string_memory_size = kwargs.pop('string_memory_size', 0x100000) #TODO: Is this actually needed for anything?
        super(StringSimProcedureMixin, self).__init__(*args, **kwargs)

    def try_load_string(self, p):
        return try_load_as_string(self.state, p)

    def load_expected_string(self, p):
        return load_expected_string(self.state, p)

    def alloc_string_memory(self, length):
        alloc_string_memory(self.state,
                            length,
                            string_memory_base=self.string_memory_base,
                            string_memory_size=self.string_memory_size)

    def constrain(self, state, constraint):
        state.add_constraints(constraint)
        state.history.add_action(SimActionConstraint(state, constraint))

    def add_ret_successor(self, state, return_val):
        ret_addr = self.cc.teardown_callsite(state, return_val,
                                             arg_types=[False] * self.num_args if self.cc.args is None else None)

        if sim_options.TRACK_JMP_ACTIONS in state.options:
            state.history.add_action(SimActionExit(state, ret_addr))

        self.successors.add_successor(state, ret_addr, self.state.solver.true, 'Ijk_Ret')
