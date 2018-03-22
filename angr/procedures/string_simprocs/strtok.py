from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin
from angr.sim_type import SimTypeString

import logging

from angr.utils.strings import load_expected_string
from claripy import StrIndexOf, Substr

l = logging.getLogger("angr.procedures.libc.strtok")

class strtok(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    def run(self, haystack_addr, needle_addr, haystack_strlen=None, needle_strlen=None):
        self.argument_types = { 0: self.ty_ptr(SimTypeString()),
                                1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        haystack = self.state.solver.eval_one(haystack_addr) # we expect a single-valued address
        needle = self.state.solver.eval_one(needle_addr) # we expect a single-valued address

        if haystack != 0:
            self.state.globals['strtok_tokenized_string'] = self.load_expected_string(haystack)
            self.state.globals['strok_to_concat_with'] = claripy.StringS('free_strtok_helper', haystack.string_length)

        string = self.state.globals['strtok_tokenized_string']
        current_concat = self.state.globals['strtok_to_concat_with']

        str_needle = self.load_expected_string(needle)

        import ipdb; ipdb.set_trace()
        result_mem_ptr = self.alloc_string_memory(str_haystack.string_length)

        ind = StrIndexOf(str_haystack, str_needle, self.state.arch.bits)

        to_store = Substr(ind, -1, str_haystack)
        self.state.memory.store(result_mem_ptr, to_store)
        return result_mem_ptr
