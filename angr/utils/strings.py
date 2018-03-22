from claripy import String, StringV
from claripy.ast.bv import BV


def stop_exception(**kwargs):
    return kwargs.get('exception') is not None


def stop_symbolic(**kwargs):
    return stop_exception(**kwargs) or kwargs.get('val').symbolic


def stop_symbolic_or_null_byte(**kwargs):
    solver = kwargs.get('state').solver
    return stop_symbolic(**kwargs) or any(solver.eval(b == 0) is not False for b in kwargs.get('val').chop(8))

def stop_no_string(**kwargs):
    return stop_exception(**kwargs)


def do_load_binary_search(state, addr, stop_point):
    lower = 0
    upper = 1

    def success(v):
        try:
            val = state.memory.load(addr, v)
            exception = None
        except Exception as e:
            val = None
            exception = e

        if stop_point(state=state, addr=addr, cur_offset=upper, val=val, exception=exception):
            return False

        return True

    while success(upper):
        lower = upper
        upper *= 2

    while abs(lower - upper) >= 2:
        guess = (lower + upper) / 2
        if success(guess):
            lower = guess
        else:
            upper = guess

    return lower


def try_load_as_string(state, addr):
    first_char = state.memory.load(addr, 1)
    if type(first_char) == String:
        length = do_load_binary_search(state, addr, stop_no_string)
        string_val = state.memory.load(addr, length)
        return string_val
    elif type(first_char) == BV and not first_char.symbolic:
        strlen = do_load_binary_search(state, addr, stop_symbolic_or_null_byte)
        string_val = state.solver.eval_one(state.memory.load(addr, strlen), cast_to=str)
        return StringV(string_val)
    else:
        return None

def load_expected_string(state, addr):
    s = try_load_as_string(state, addr)
    if s is None:
        raise ValueError("Expected to be able to load a string but could not!")
    return s

