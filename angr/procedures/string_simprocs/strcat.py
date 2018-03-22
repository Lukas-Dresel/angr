from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin
from angr.sim_type import SimTypeString
from claripy import StrConcat


class strcat(SimProcedure, StringSimProcedureMixin):
    def run(self, dst, src):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        str_dst = self.load_expected_string(dst)
        str_src = self.load_expected_string(src)

        self.state.memory.store(dst, StrConcat(str_dst, str_src))
        return dst
