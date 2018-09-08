import claripy
from .plugin import SimStatePlugin


def translate_StringS(state, expr, args):
    var_name, uninitialized = args
    # We need to pass through the state plugin because we need to trigger the
    # hook on the new symbolic variable creation
    return state.se.BVS(var_name.replace(
        claripy.String.STRING_TYPE_IDENTIFIER,
        claripy.String.GENERATED_BVS_IDENTIFIER), expr.length)


def translate_StrExtract(state, expr, args):
    start_byte, length_extract, bv_to_be_extracted = args
    return claripy.Extract(
        (start_byte + length_extract)*8 - 1, start_byte*8, bv_to_be_extracted
    )


def translate_StrReverse(state, expr, args):
    bv_to_be_reversed, = args
    return bv_to_be_reversed.reversed


def translate__ne__(state, constraint, fixed_args):
    left_operand, right_operand = fixed_args
    if isinstance(left_operand, claripy.ast.BV) and left_operand.concrete:
        left_operand = claripy.StringV(chr(state.se.eval_one(left_operand)))
    if isinstance(right_operand, claripy.ast.BV) and right_operand.concrete:
        right_operand = claripy.StringV(chr(state.se.eval_one(right_operand)))
    return left_operand != right_operand


EXPRESSIONS_TRANSLATION_TABLE = {
    'StrReverse': translate_StrReverse,
    'StrExtract': translate_StrExtract,
    'StringS':  translate_StringS
}

CONSTRAINTS_TRANSLATION_TABLE = {
    '__ne__': translate__ne__,
    'StrExtract': translate_StrExtract,
    'StringS':  translate_StringS
}


class SimStateTranslator(SimStatePlugin):
    """
    This state translate BV constraints in STRING constraints
    """
    def __init__(self):
        SimStatePlugin.__init__(self)

        # Table holding a mapping between BV variables and STRING variable
        self.alias_table = {}
        self.translation_table = {}

    def add_variable_alias(self, var_name, alias_name):
       self.alias_table[var_name] = alias_name

    def _get_original_expr_before_translation(self, expr):
        if isinstance(expr, claripy.ast.Base) and expr._hash in self.translation_table.keys():
            return self.translation_table[expr._hash]
        return expr

    def translate_constraint(self, constraint):
        if constraint.op in CONSTRAINTS_TRANSLATION_TABLE.keys():
            fixed_args = [self._get_original_expr_before_translation(arg) for arg in constraint.args]
            if any(isinstance(arg, claripy.ast.String) for arg in fixed_args):
                return CONSTRAINTS_TRANSLATION_TABLE[constraint.op](self.state, constraint, fixed_args),
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
            print "++++++++++++++++++++++++++++++======="
            print "Unknown operation {} \t ignoring...".format(expr.op)
            print "++++++++++++++++++++++++++++++======="
            return expr,
        else:
            translated_expr = EXPRESSIONS_TRANSLATION_TABLE[expr.op](self.state, expr, args)
            # print "translated {} to {}".format(expr, translated_expr)
            self.populate_translation_table(translated_expr._hash, expr)
            # print self.translation_table
            return translated_expr,

    def translate_expression(self, expr):
        """
        Browse the AST that has to be translated and translates it starting from the leaf
        :param expr:
        :return:
        """
        if not isinstance(expr, claripy.ast.String):
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
        c.allocation_base = self.alias_table.copy()
        return c

    # def _combine(self, others):
    #     merging_occured = False
    #
    #     new_allocation_base = max(o.allocation_base for o in others)
    #     if self.state.se.symbolic(new_allocation_base):
    #         raise ValueError("wat")
    #
    #     concrete_allocation_base = (
    #         self.allocation_base
    #         if type(self.allocation_base) in (int, long) else
    #         self.state.se.eval(self.allocation_base)
    #     )
    #
    #     concrete_new_allocation_base = (
    #         new_allocation_base
    #         if type(new_allocation_base) in (int, long) else
    #         self.state.se.eval(new_allocation_base)
    #     )
    #
    #     if concrete_allocation_base != concrete_new_allocation_base:
    #         self.allocation_base = new_allocation_base
    #         merging_occured = True
    #
    #     return merging_occured
    #
    # def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
    #     return self._combine(others)
    #
    # def widen(self, others):
    #     return self._combine(others)


from angr.sim_state import SimState
SimState.register_default('translator', SimStateTranslator)
