import claripy
from angr.utils.strings import try_load_as_string, load_expected_string

class StringSimProcedureMixin(object):
    def __init__(self, *args, **kwargs):
        self.string_memory_base = kwargs.pop('string_memory_base', 0xdead0000)
        self.string_memory_size = kwargs.pop('string_memory_size', 0x100000)
        super(StringSimProcedureMixin, self).__init__(*args, **kwargs)

    @property
    def next_string_alloc_addr(self):
        return self.state.globals.get('next_string_alloc_addr', self.string_memory_base) if self.state is not None else self.string_memory_base

    @next_string_alloc_addr.setter
    def next_string_alloc_addr(self, x):
        self.state.globals['next_string_alloc_addr'] = x

    def alloc_string_memory(self, length):
        ptr = self.next_string_alloc_addr
        self.state.memory.store(ptr, claripy.BVV(0, (length + 1) * 8))
        self.next_string_alloc_addr += (length + 1)
        return ptr

    def try_load_string(self, p):
        return try_load_as_string(self.state, p)

    def load_expected_string(self, p):
        return load_expected_string(self.state, p)

