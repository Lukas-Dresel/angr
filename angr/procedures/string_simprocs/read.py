import angr

######################################
# read
######################################
from claripy import StringS


class read(angr.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd, dst, length):
        if length.symbolic or fd.symbolic:
            raise NotImplementedError

        _fd = self.state.solver.eval_one(fd)
        len = self.state.solver.eval_one(length)
        new_var = StringS('symbolic_read_fd:{}'.format(_fd), len)
        self.state.memory.store(dst, new_var)
        return length
