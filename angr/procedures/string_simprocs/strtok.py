import claripy
from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin
from angr.sim_type import SimTypeString

import logging

from angr.utils.strings import load_expected_string
from claripy import StrIndexOf, StrSubstr, StrLen, StrConcat

l = logging.getLogger("angr.procedures.libc.strtok")

class strtok(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    def strlen(self, s):
        return StrLen(s, self.state.arch.bits)

    def run(self, haystack_addr, needle_addr, haystack_strlen=None, needle_strlen=None):
        self.argument_types = { 0: self.ty_ptr(SimTypeString()),
                                1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        haystack = self.state.solver.eval_one(haystack_addr) # we expect a single-valued address
        needle = self.state.solver.eval_one(needle_addr) # we expect a single-valued address

        #import ipdb; ipdb.set_trace()
        str_needle = self.load_expected_string(needle)

        if haystack != 0:
            str_haystack = self.load_expected_string(haystack)
            str_len_processed = claripy.BVV(0, self.state.arch.bits)
            self.state.globals['strtok_tokenized_string'] = str_haystack
            self.state.globals['strtok_len_already_processed'] = str_len_processed

        string_to_tokenize = self.state.globals['strtok_tokenized_string']
        current_start_idx = self.state.globals['strtok_len_already_processed']

        new_index = StrIndexOf(string_to_tokenize, str_needle, current_start_idx, self.state.arch.bits)

        current_token = StrSubstr(current_start_idx, new_index, string_to_tokenize)

        self.state.globals['strtok_len_already_processed'] = new_index + 1

        result_mem_ptr = self.alloc_string_memory(current_token.string_length)
        self.state.memory.store(result_mem_ptr, current_token)

        return claripy.If(new_index >= 0, result_mem_ptr, claripy.BVV(0, self.state.arch.bits))
