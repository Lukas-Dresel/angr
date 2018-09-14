import logging
import claripy
from .plugin import SimStatePlugin

l = logging.getLogger("angr.state_plugins.translator")


def _normalize_args(state, args):
    """
    This function translate the ascii value encoded in the BV
    as a StringV holding the corresponding bytes of the ascii character
    :param state: State of the program at that point
    :param args: arguments that has to be translated
    :return:
    """
    left_operand, right_operand = args
    if isinstance(left_operand, claripy.ast.BV) and left_operand.concrete:
        left_operand = claripy.StringV(chr(state.se.eval_one(left_operand)))
    if isinstance(right_operand, claripy.ast.BV) and right_operand.concrete:
        right_operand = claripy.StringV(chr(state.se.eval_one(right_operand)))
    return left_operand, right_operand

def _build_if_constraint(data, pattern, start_bit, arch_bits):
    msb = data.length - start_bit - 1
    lsb = msb - pattern.length + 1
    if start_bit == data.length - pattern.length:
        return claripy.If(data[msb:lsb] == pattern, msb, claripy.BVV(0x0, arch_bits))
    else:
        return claripy.If(
            data[msb:lsb] == pattern,
            claripy.BVV(msb, arch_bits),
            _build_if_constraint(data, pattern, start_bit + 8, arch_bits)
        )


# ---------------------- Expressions translation routines ----------------------

def translate_expr__add__(state, expr, args):
    left_operand, right_operand, = args
    return left_operand + right_operand

def translate_expr_StringS(state, expr, args):
    var_name, uninitialized = args
    # We need to pass through the state plugin because we need to trigger the
    # hook on the new symbolic variable creation
    return state.se.BVS(var_name.replace(
        claripy.String.STRING_TYPE_IDENTIFIER,
        claripy.String.GENERATED_BVS_IDENTIFIER), expr.length)

def translate_expr_StringV(state, expr, args):
    string_value, _ = args
    return state.se.BVV(string_value)

def translate_expr_StrExtract(state, expr, args):
    start_byte, length_extract, bv_to_be_extracted = args
    return claripy.Extract(
        (start_byte + length_extract)*8 - 1, start_byte*8, bv_to_be_extracted
    )

def translate_expr_StrIndexOf(state, expr, args):
    data, pattern, start_byte, arch_bits = args
    res = _build_if_constraint(data, pattern, state.se.eval(start_byte, 1)*8, arch_bits)
    return res

def translate_expr_StrReverse(state, expr, args):
    bv_to_be_reversed, = args
    return bv_to_be_reversed.reversed

# ---------------------- Constraints translation routines ----------------------

def translate_constraint__ne__(state, constraint, fixed_args):
    left_operand, right_operand = _normalize_args(state, fixed_args)
    return left_operand != right_operand


def translate_constraint__eq__(state, constraint, fixed_args):
    left_operand, right_operand = _normalize_args(state, fixed_args)
    return left_operand == right_operand


def translate_constraint__gt__(state, constraint, fixed_args):
    left_operand, right_operand = _normalize_args(state, fixed_args)
    return left_operand > right_operand


def translate_constraint__ge__(state, constraint, fixed_args):
    left_operand, right_operand = _normalize_args(state, fixed_args)
    return left_operand >= right_operand


def translate_constraint__lt__(state, constraint, fixed_args):
    left_operand, right_operand = _normalize_args(state, fixed_args)
    return left_operand < right_operand


def translate_constraint__le__(state, constraint, fixed_args):
    left_operand, right_operand = _normalize_args(state, fixed_args)
    return left_operand <= right_operand



EXPRESSIONS_TRANSLATION_TABLE = {
    'StringS':  translate_expr_StringS,
    'StringV': translate_expr_StringV,
    'StrReverse': translate_expr_StrReverse,
    'StrExtract': translate_expr_StrExtract,
    'StrIndexOf': translate_expr_StrIndexOf,
    '__add__': translate_expr__add__,
}

CONSTRAINTS_TRANSLATION_TABLE = {
    '__ne__': translate_constraint__ne__,
    '__eq__': translate_constraint__eq__,
    '__gt__': translate_constraint__gt__,
    '__ge__': translate_constraint__ge__,
    '__lt__': translate_constraint__lt__,
    '__le__': translate_constraint__le__,
}


class SimStateTranslator(SimStatePlugin):
    """
    This state translate BV constraints in STRING constraints
    """
    def __init__(self):
        SimStatePlugin.__init__(self)
        # Table holding the mapping between operations and the correct translation routine
        self.translation_table = {}

    def _get_original_expr_before_translation(self, expr):
        if isinstance(expr, claripy.ast.Base) and expr._hash in self.translation_table.keys():
            return self.translation_table[expr._hash]
        return expr

    def translate_constraint(self, constraint):
        if constraint.op in CONSTRAINTS_TRANSLATION_TABLE.keys():
            fixed_args = [self._get_original_expr_before_translation(arg) for arg in constraint.args]
            if any(isinstance(arg, claripy.ast.String) for arg in fixed_args):
                return CONSTRAINTS_TRANSLATION_TABLE[constraint.op](self.state, constraint, fixed_args),
            else:
                l.debug('Skipping translation of %r (operation: %r)', constraint, constraint.op)
        return constraint,

    def populate_translation_table(self, translated_hash, non_translated_expr):
        """
        Populates the table  holding the map between:
            - the hash of the translated_expression
            - the initial expression before the translation
        :param translated_hash: hash of the translated expression
        :param non_translated_expr: initial expression before the translation
        """
        self.translation_table[translated_hash] = non_translated_expr

    def translate_expression_helper(self, expr, args=()):
        """
        Check if it's possible to translate a node of the AST and if so it applies the appropriate
        translation routine for that node
        :param expr: node that has to be translated
        :param args: arguments which have to be passed to the translation function
                     (e. g. in case of the translation from StringS to BVS the arguments are the name, the length etc..)
        :return:
        """
        if expr.op not in EXPRESSIONS_TRANSLATION_TABLE.keys():
            l.debug("Unknown expression %s... ignoring...", expr.op)
            return expr,
        else:
            translated_expr = EXPRESSIONS_TRANSLATION_TABLE[expr.op](self.state, expr, args)
            self.populate_translation_table(translated_expr._hash, expr)
            l.debug("Translating %r to %r", expr, translated_expr)
            return translated_expr,

    def translate_expression(self, expr):
        """
        Browse the AST that has to be translated and translates it starting from the leaf
        :param expr:
        :return:
        """
        if not isinstance(expr, claripy.ast.Base):
            return expr,
        if not expr.args:
            return self.translate_expression_helper(expr)
        else:
            args = ()
            for arg in expr.args:
                args += self.translate_expression(arg)
            return self.translate_expression_helper(expr, args)

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        c = SimStateTranslator()
        c.translation_table = self.translation_table.copy()
        return c


from angr.sim_state import SimState
SimState.register_default('translator', SimStateTranslator)
