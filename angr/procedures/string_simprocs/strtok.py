import claripy
from angr import SimProcedure, sim_options
from angr.procedures.string_simprocs import StringSimProcedureMixin, alloc_string_memory
from angr.sim_type import SimTypeString

import logging

from angr.state_plugins import SimActionExit, SimActionConstraint
from angr.utils.strings import load_expected_string
from claripy import StrIndexOf, StrSubstr, StrLen, StrConcat

l = logging.getLogger("angr.procedures.libc.strtok")

class strtok(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    # we add successors manually! NO_RET to avoid the default state being added as a successor
    NO_RET = True

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

        # State where it wasn't found.
        failed_state = self.state.copy()
        self.constrain(failed_state, new_index < 0)
        self.add_ret_successor(failed_state, claripy.BVV(0, self.state.arch.bits))

        success_state = self.state.copy()

        current_token = StrSubstr(current_start_idx, new_index, string_to_tokenize)

        success_state.globals['strtok_len_already_processed'] = new_index + 1
        result_mem_ptr = alloc_string_memory(self.state, current_token.string_length)
        self.state.memory.store(result_mem_ptr, current_token)

        self.constrain(success_state, new_index >= 0)
        self.add_ret_successor(success_state, claripy.BVV(result_mem_ptr, self.state.arch.bits))

    def constrain(self, state, constraint):
        state.add_constraints(constraint)
        state.history.add_action(SimActionConstraint(state, constraint))

    def add_ret_successor(self, state, return_val):
        ret_addr = self.cc.teardown_callsite(self.state, return_val,
                                             arg_types=[False] * self.num_args if self.cc.args is None else None)

        if sim_options.TRACK_JMP_ACTIONS in state.options:
            state.history.add_action(SimActionExit(state, ret_addr))

        self.successors.add_successor(state, ret_addr, self.state.solver.true, 'Ijk_Ret')