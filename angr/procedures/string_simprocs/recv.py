import claripy
from angr import SimProcedure
from angr.procedures.string_simprocs import StringSimProcedureMixin
from angr.sim_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("angr.procedures.libc.recv")


class recv(SimProcedure, StringSimProcedureMixin):
    #pylint:disable=arguments-differ

    def run(self, sockfd, buf, len, flags):
        length = self.state.se.eval(len)
        dst = self.state.se.eval(buf)
        fd = self.state.posix.get_fd(sockfd)  # The solver fails here if we try to evaluate the expression (BVS .. 0x0)
        data = claripy.StringS("recv_out", length)
        written_length = fd.write_data(data, length)
        self.state.memory.store(dst, data)
        return written_length

