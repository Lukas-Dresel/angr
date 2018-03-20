import angr
from angr.sim_type import SimTypeString
from angr.utils.strings import load_expected_string
from claripy import StrConcat


class strcat(angr.SimProcedure):
    def run(self, dst, src):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        str_dst = load_expected_string(self.state, dst)
        str_src = load_expected_string(self.state, src)

        self.state.memory.store(dst, StrConcat(str_dst, str_src))
        return dst
