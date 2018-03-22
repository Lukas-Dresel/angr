import angr
from angr.sim_type import SimTypeString, SimTypeInt, SimTypeFd

######################################
# open
######################################
from angr.utils.strings import try_load_as_string


class open(angr.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    def run(self, p_addr, flags):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: SimTypeInt(32, True)}
        self.return_type = SimTypeFd()

        string = try_load_as_string(self.state, p_addr)
        if string is not None:
            path = self.state.se.eval(string)

        else:
            strlen = angr.SIM_PROCEDURES['libc']['strlen']

            p_strlen = self.inline_call(strlen, p_addr)
            p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
            path = self.state.se.eval(p_expr, cast_to=str)

        fd = self.state.posix.open(path, flags)
        return fd