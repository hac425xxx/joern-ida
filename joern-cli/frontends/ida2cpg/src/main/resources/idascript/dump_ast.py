import os
import ida_lines
import ida_pro
import idaapi
import idautils
import idc
import json
from PyQt5 import QtCore

citem2str = {
    idaapi.cot_empty: "cot_empty",
    idaapi.cot_comma: "cot_comma",  # x, y
    idaapi.cot_asg: "cot_asg",  # x = y
    idaapi.cot_asgbor: "cot_asgbor",  # x |= y
    idaapi.cot_asgxor: "cot_asgxor",  # x ^= y
    idaapi.cot_asgband: "cot_asgband",  # x &= y
    idaapi.cot_asgadd: "cot_asgadd",  # x += y
    idaapi.cot_asgsub: "cot_asgsub",  # x -= y
    idaapi.cot_asgmul: "cot_asgmul",  # x *= y
    idaapi.cot_asgsshr: "cot_asgsshr",  # x >>= y signed
    idaapi.cot_asgushr: "cot_asgushr",  # x >>= y unsigned
    idaapi.cot_asgshl: "cot_asgshl",  # x <<= y
    idaapi.cot_asgsdiv: "cot_asgsdiv",  # x /= y signed
    idaapi.cot_asgudiv: "cot_asgudiv",  # x /= y unsigned
    idaapi.cot_asgsmod: "cot_asgsmod",  # x %= y signed
    idaapi.cot_asgumod: "cot_asgumod",  # x %= y unsigned
    idaapi.cot_tern: "cot_tern",  # x ? y : z
    idaapi.cot_lor: "cot_lor",  # x || y
    idaapi.cot_land: "cot_land",  # x && y
    idaapi.cot_bor: "cot_bor",  # x | y
    idaapi.cot_xor: "cot_xor",  # x ^ y
    idaapi.cot_band: "cot_band",  # x & y
    idaapi.cot_eq: "cot_eq",  # x == y int or fpu (see EXFL_FPOP)
    idaapi.cot_ne: "cot_ne",  # x != y int or fpu (see EXFL_FPOP)
    idaapi.cot_sge: "cot_sge",  # x >= y signed or fpu (see EXFL_FPOP)
    idaapi.cot_uge: "cot_uge",  # x >= y unsigned
    idaapi.cot_sle: "cot_sle",  # x <= y signed or fpu (see EXFL_FPOP)
    idaapi.cot_ule: "cot_ule",  # x <= y unsigned
    idaapi.cot_sgt: "cot_sgt",  # x >  y signed or fpu (see EXFL_FPOP)
    idaapi.cot_ugt: "cot_ugt",  # x >  y unsigned
    idaapi.cot_slt: "cot_slt",  # x <  y signed or fpu (see EXFL_FPOP)
    idaapi.cot_ult: "cot_ult",  # x <  y unsigned
    idaapi.cot_sshr: "cot_sshr",  # x >> y signed
    idaapi.cot_ushr: "cot_ushr",  # x >> y unsigned
    idaapi.cot_shl: "cot_shl",  # x << y
    idaapi.cot_add: "cot_add",  # x + y
    idaapi.cot_sub: "cot_sub",  # x - y
    idaapi.cot_mul: "cot_mul",  # x * y
    idaapi.cot_sdiv: "cot_sdiv",  # x / y signed
    idaapi.cot_udiv: "cot_udiv",  # x / y unsigned
    idaapi.cot_smod: "cot_smod",  # x % y signed
    idaapi.cot_umod: "cot_umod",  # x % y unsigned
    idaapi.cot_fadd: "cot_fadd",  # x + y fp
    idaapi.cot_fsub: "cot_fsub",  # x - y fp
    idaapi.cot_fmul: "cot_fmul",  # x * y fp
    idaapi.cot_fdiv: "cot_fdiv",  # x / y fp
    idaapi.cot_fneg: "cot_fneg",  # -x fp
    idaapi.cot_neg: "cot_neg",  # -x
    idaapi.cot_cast: "cot_cast",  # (type)x
    idaapi.cot_lnot: "cot_lnot",  # !x
    idaapi.cot_bnot: "cot_bnot",  # ~x
    idaapi.cot_ptr: "cot_ptr",  # *x, access size in 'ptrsize'
    idaapi.cot_ref: "cot_ref",  # &x
    idaapi.cot_postinc: "cot_postinc",  # x++
    idaapi.cot_postdec: "cot_postdec",  # x--
    idaapi.cot_preinc: "cot_preinc",  # ++x
    idaapi.cot_predec: "cot_predec",  # --x
    idaapi.cot_call: "cot_call",  # x(...)
    idaapi.cot_idx: "cot_idx",  # x[y]
    idaapi.cot_memref: "cot_memref",  # x.m
    idaapi.cot_memptr: "cot_memptr",  # x->m, access size in 'ptrsize'
    idaapi.cot_num: "cot_num",  # n
    idaapi.cot_fnum: "cot_fnum",  # fpc
    idaapi.cot_str: "cot_str",  # string constant (user representation)
    idaapi.cot_obj: "cot_obj",  # obj_ea
    idaapi.cot_var: "cot_var",  # v
    idaapi.cot_insn: "cot_insn",  # instruction in expression, internal representation only
    idaapi.cot_sizeof: "cot_sizeof",  # sizeof(x)
    idaapi.cot_helper: "cot_helper",  # arbitrary name
    idaapi.cot_type: "cot_type",  # arbitrary type
    idaapi.cit_empty: "cit_empty",  # instruction types start here
    idaapi.cit_block: "cit_block",  # block-statement: { ... }
    idaapi.cit_expr: "cit_expr",  # expression-statement: expr;
    idaapi.cit_if: "cit_if",  # if-statement
    idaapi.cit_for: "cit_for",  # for-statement
    idaapi.cit_while: "cit_while",  # while-statement
    idaapi.cit_do: "cit_do",  # do-statement
    idaapi.cit_switch: "cit_switch",  # switch-statement
    idaapi.cit_break: "cit_break",  # break-statement
    idaapi.cit_continue: "cit_continue",  # continue-statement
    idaapi.cit_return: "cit_return",  # return-statement
    idaapi.cit_goto: "cit_goto",  # goto-statement
    idaapi.cit_asm: "cit_asm",  # asm-statement
}


def citem_to_str(c):
    ea = c.ea
    if ea == 0xFFFFFFFFFFFFFFFF:
        ea = 0
    s = "0x{:x}: {}".format(ea, citem2str[c.op])
    # s += " {}".format(get_citem_name(c))
    return s


def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.

    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.

    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.

    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == idaapi.COLOR_ADDR:
                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i:i + idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes


def map_line2citem(cfunc: idaapi.cfunc_t):
    decompilation_text = cfunc.get_pseudocode()

    """
    Map decompilation line numbers to citems.

    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.

    Output:

        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '

    """
    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    citem2line = {}
    for line_number in range(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        indexs = lex_citem_indexes(line_text)

        citems = []
        treeitems = cfunc.treeitems

        for i in indexs:
            # print(i)
            try:
                item = treeitems[i]
                address = item.ea
                citems.append("0x{:x}".format(address))
            except:
                pass

        for c in citems:
            citem2line[c] = line_number

        line2citem[line_number] = citems
        # logger.debug("Line Text: %s" % binascii.hexlify(line_text))

    return line2citem


class AstDumper(idaapi.ctree_visitor_t):
    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_POST)
        self.ast_nodes = []
        self.ast_nodes.append({})
        self.prev_level = self.ast_nodes[0]
        self.curr_level = self.ast_nodes[0]

        self.level_stack = []

    def visit_insn(self, i):
        self.level_stack.append(self.curr_level)
        self.curr_level["type"] = citem_to_str(i)
        print("visit_insn: {}".format(citem_to_str(i)))
        return 0

    def leave_insn(self, i) -> int:
        print("leave_insn: {}".format(citem_to_str(i)))
        return 0

    def visit_expr(self, e) -> int:
        print("visit_expr: {}".format(citem_to_str(e)))
        return 0

    def leave_expr(self, e) -> int:
        print("leave_expr: {}".format(citem_to_str(e)))
        return 0


def get_citem_name(c: idaapi.citem_t):
    if hasattr(c, "dstr"):
        return c.dstr()
    else:
        name = c.print1(None)
        name = ida_lines.tag_remove(name)
        name = ida_pro.str2user(name)
        return name


class AstNode:

    @staticmethod
    def createAttr(ea, index):
        ea = ea & 0xfffffff

        if ea == idaapi.BADADDR:
            ea = 0
        else:
            ea = ea - idaapi.get_imagebase()

        r = {
            "ea": "{}".format(ea),
            "treeindex": str(index)
        }
        return r

    @staticmethod
    def createIdentifierNode(c: idaapi.citem_t, name, typ="void *"):
        n = {
            "nodeType": "Identifier",
            "code": get_citem_name(c),
            "attributes": AstNode.createAttr(c.ea, c.index),
            "name": name,
            "type": typ
        }
        return n

    @staticmethod
    def createStringNode(c: idaapi.citem_t, value):
        n = {
            "nodeType": "String",
            "code": get_citem_name(c),
            "attributes": AstNode.createAttr(c.ea, c.index),
            "value": value
        }
        return n

    @staticmethod
    def createNumberNode(c: idaapi.citem_t, v):
        n = {
            "nodeType": "Number",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "value": str(v)
        }
        return n

    @staticmethod
    def createMemberPtrNode(c: idaapi.citem_t, base, member):
        n = {
            "nodeType": "MemberPtr",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "base": base,
            "member": member
        }
        return n

    @staticmethod
    def createMemberRefNode(c: idaapi.citem_t, base, member):
        n = {
            "nodeType": "MemberRef",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "base": base,
            "member": member
        }
        return n

    @staticmethod
    def createTernNode(c: idaapi.citem_t, cond, then, els):
        n = {
            "nodeType": "Tern",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "cond": cond,
            "if": then,
            "else": els
        }
        return n

    @staticmethod
    def createReturnNode(c: idaapi.citem_t, e):
        n = {
            "nodeType": "Return",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "expr": e
        }
        return n

    @staticmethod
    def createIfNode(c: idaapi.citem_t, cond, ithen, ielse):
        n = {
            "nodeType": "If",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "cond": cond,
            "then": ithen,
            "else": ielse,
        }
        return n

    @staticmethod
    def createWhileNode(c: idaapi.citem_t, cond, body):
        n = {
            "nodeType": "While",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "cond": cond,
            "body": body,
        }
        return n

    @staticmethod
    def createDoNode(c: idaapi.citem_t, cond, body):
        n = {
            "nodeType": "Do",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "cond": cond,
            "body": body,
        }
        return n

    @staticmethod
    def createForNode(c: idaapi.citem_t, cond, init, step, body):
        n = {
            "nodeType": "For",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "cond": cond,
            "init": init,
            "step": step,
            "body": body,
        }
        return n

    @staticmethod
    def createSwitchNode(c: idaapi.citem_t, cond, cases):
        n = {
            "nodeType": "Switch",
            "code": get_citem_name(c),
            "attributes": AstNode.createAttr(c.ea, c.index),
            "cond": cond,
            "cases": cases,
        }
        return n

    @staticmethod
    def createGotoNode(c: idaapi.citem_t, target: idaapi.citem_t, label):
        n = {
            "nodeType": "Goto",
            "code": get_citem_name(c),
            "attributes": AstNode.createAttr(c.ea, c.index),
            "target": AstNode.createAttr(target.ea, target.index),
            "label": "LABEL_{}".format(label)
        }
        return n

    @staticmethod
    def createBreakNode(c: idaapi.citem_t):
        n = {
            "nodeType": "Break",
            "code": get_citem_name(c),
            "attributes": AstNode.createAttr(c.ea, c.index),
        }
        return n

    @staticmethod
    def createCastNode(c: idaapi.citem_t, e, type):
        n = {
            "nodeType": "Cast",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "expr": e,
            "type": type
        }
        return n

    @staticmethod
    def createStarNode(c: idaapi.citem_t, e):
        n = {
            "nodeType": "Star",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "expr": e
        }
        return n

    @staticmethod
    def createBlockNode(c: idaapi.citem_t, stmts):
        n = {
            "nodeType": "Block",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "stmts": stmts
        }
        return n

    @staticmethod
    def createCallNode(c: idaapi.citem_t, name, args):
        n = {
            "nodeType": "Call",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "name": name,
            "args": args
        }
        return n

    @staticmethod
    def createUnaryNode(c: idaapi.citem_t, op, expr):
        n = {
            "nodeType": op,
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "expr": expr
        }
        return n

    @staticmethod
    def createEmptyNode(c: idaapi.citem_t):
        n = {
            "nodeType": "Empty",
            "code": get_citem_name(c),
            "attributes": AstNode.createAttr(c.ea, c.index),
        }
        return n

    @staticmethod
    def createBinaryOpNode(c: idaapi.citem_t, op, left, right):
        n = {
            "nodeType": op,
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "left": left,
            "right": right
        }
        return n

    @staticmethod
    def createArrayIndexNode(c: idaapi.citem_t, base, idx):
        n = {
            "nodeType": "ArrayIndexAccess",
            "code": get_citem_name(c),

            "attributes": AstNode.createAttr(c.ea, c.index),
            "base": base,
            "index": idx
        }
        return n

    @staticmethod
    def createFunctionNode(ea, code, name, paramters, locals, body, return_type):
        n = {
            "nodeType": "Function",
            "attributes": AstNode.createAttr(ea, -1),
            "namespacedName": "<global>",
            "name": name,
            "code": code,
            "paramters": paramters,
            "localDecls": locals,
            "body": body,
            "returnType": return_type
        }
        return n

    @staticmethod
    def createParameterNode(ea, name, type, code):
        n = {
            "nodeType": "Parameter",
            "attributes": AstNode.createAttr(ea, -1),
            "code": code,
            "name": name,
            "type": type,
        }
        return n

    @staticmethod
    def createLocalDeclNode(ea, name, type, code):
        n = {
            "nodeType": "LocalDecl",
            "attributes": AstNode.createAttr(ea, -1),
            "code": code,
            "name": name,
            "type": type,
        }
        return n

    @staticmethod
    def createExpressionNode(c: idaapi.citem_t, expr):
        n = {
            "nodeType": "Expression",
            "code": get_citem_name(c),
            "attributes": AstNode.createAttr(c.ea, c.index),
            "expr": expr,
        }
        return n

    @staticmethod
    def createLabelNode(c: idaapi.citem_t, label):
        n = {
            "nodeType": "Label",
            "code": get_citem_name(c),
            "attributes": AstNode.createAttr(c.ea, c.index),
            "name": "LABEL_{}".format(label),
        }
        return n


class fake_citem_t:
    def __init__(self, ea, code, index=-1):
        self.ea = ea
        self.code = code
        self.index = index

    def dstr(self, *args):
        return self.code


class AstWalkDumper:
    def __init__(self) -> None:
        self.stack = []

    def push_item(self, c):
        self.stack.append(c)

    def pop_item(self):
        return self.stack.pop()

    def get_type_string(self, tf):
        pass

    def dump_stack(self):
        while len(self.stack):
            x: idaapi.citem_t = self.stack.pop()
            print("stack: {}".format(citem_to_str(x)))

    def walk_func(self, ea: int):
        fname = idaapi.get_name(ea)
        try:
            self.cfunc = idaapi.decompile(ea)
            if not self.cfunc:
                print("[*] Error decompile {}".format(fname))
                return None
        except Exception as e:
            print(e)
            print("[*] Error decompile {}".format(fname))
            return None

        tf = idaapi.tinfo_t()
        self.cfunc.get_func_type(tf)
        ret_type = str(tf.get_rettype())
        lines = []
        sv = self.cfunc.get_pseudocode()
        for sline in sv:
            line = idaapi.tag_remove(sline.line)
            lines.append(line)
        code = "\n".join(lines)

        self.label2citem = {}
        i: idaapi.citem_t = None
        for i in self.cfunc.treeitems:
            label = i.label_num
            if label != -1:
                # print("Label Info: " + str(label) + "  " + citem_to_str(i))
                self.label2citem[label] = i

        body = self.walk_insn(self.cfunc.body)
        lvars = self.cfunc.get_lvars()
        lv: idaapi.lvar_t = None

        param_idx = []

        params = []
        for a in self.cfunc.argidx:
            param_idx.append(a)
            lv = lvars[a]
            type = str(lv.tif)
            var_name = lv.name
            vc = "{} {}".format(type, var_name)
            params.append(AstNode.createParameterNode(ea, var_name, type, vc))

        locals = []
        for idx, lv in enumerate(lvars):
            # 忽略参数
            if idx in param_idx:
                continue

            # print(idx, lv.name)
            type = str(lv.tif)
            var_name = lv.name
            vc = "{} {}".format(type, var_name)
            locals.append(AstNode.createLocalDeclNode(ea, var_name, type, vc))

        n = AstNode.createFunctionNode(ea, code, fname, params, locals, [body], ret_type)
        return n

    def walk_block(self, i: idaapi.cinsn_t):
        stmts = []
        for i in i.cblock:
            stmts.append(self.walk_insn(i))
        n = AstNode.createBlockNode(i, stmts)
        return n

    def walk_return(self, i: idaapi.cinsn_t):
        x = self.walk_expr(i.creturn.expr)
        # print(x)

        dummy_ctiem = fake_citem_t(i.ea, "ida2cpg_return_val")
        y = AstNode.createIdentifierNode(dummy_ctiem, "ida2cpg_return_val")

        dummy_ctiem.code = "ida2cpg_return_val = {}".format(x["code"])
        ass = AstNode.createExpressionNode(dummy_ctiem, AstNode.createBinaryOpNode(dummy_ctiem, "cot_asg", y, x))

        dummy_ctiem.code = "return ida2cpg_return_val;"
        n = AstNode.createReturnNode(dummy_ctiem, y)
        block = AstNode.createBlockNode(i, [ass, n])
        return block

    def walk_if(self, i: idaapi.cinsn_t):
        cif: idaapi.cif_t = i.cif
        cond = self.walk_expr(cif.expr)
        then_stmt = [self.walk_insn(cif.ithen)]

        else_stmt = None
        if cif.ielse:
            else_stmt = [self.walk_insn(cif.ielse)]

        n = AstNode.createIfNode(i, cond, then_stmt, else_stmt)
        return n

    def walk_while(self, i: idaapi.cinsn_t):
        cwhile: idaapi.cwhile_t = i.cwhile
        cond = self.walk_expr(cwhile.expr)
        body = self.walk_insn(cwhile.body)
        n = AstNode.createWhileNode(i, cond, body)
        return n

    def walk_do(self, i: idaapi.cinsn_t):
        cdo: idaapi.cdo_t = i.cdo
        cond = self.walk_expr(cdo.expr)
        body = self.walk_insn(cdo.body)
        n = AstNode.createDoNode(i, cond, body)
        return n

    def walk_for(self, i: idaapi.cinsn_t):
        cfor: idaapi.cfor_t = i.cfor
        init = self.walk_expr(cfor.init)
        step = self.walk_expr(cfor.step)
        cond = self.walk_expr(cfor.expr)
        body = self.walk_insn(cfor.body)
        n = AstNode.createForNode(i, cond, init, step, body)
        return n

    def walk_switch(self, i: idaapi.cinsn_t):
        cswitch: idaapi.cswitch_t = i.cswitch
        cond = self.walk_expr(cswitch.expr)

        cases = []
        case: idaapi.ccase_t = None
        for case in cswitch.cases:
            values = [v for v in case.values]
            stmts = self.walk_insn(case)
            cases.append((values, stmts))

        n = AstNode.createSwitchNode(i, cond, cases)
        return n

    def walk_goto(self, i: idaapi.cinsn_t):
        cgoto: idaapi.cgoto_t = i.cgoto
        label = cgoto.label_num
        target = self.label2citem[label]
        n = AstNode.createGotoNode(i, target, label)
        return n

    def walk_break(self, i: idaapi.cinsn_t):
        n = AstNode.createBreakNode(i)
        return n

    def walk_var_expr(self, e: idaapi.cexpr_t):
        lvars_idx = e.v.idx  # get index
        lvars = self.cfunc.get_lvars()  # lvars_t

        var: idaapi.lvar_t = lvars[lvars_idx]  # var_t
        name = var.name
        typ = str(var.tif)

        n = AstNode.createIdentifierNode(e, name, typ)
        return n

    def walk_cast_expr(self, e: idaapi.cexpr_t):
        v = self.walk_expr(e.x)
        t = str(e.type)
        r = AstNode.createCastNode(e, v, t)
        return r

    def walk_sizeof_expr(self, e: idaapi.cexpr_t):
        v = e.x.type.get_size()
        r = AstNode.createNumberNode(e, v)
        return r

    def get_member_of_offset(self, t: idaapi.tinfo_t, off):
        s = t.dstr()
        sid = idaapi.get_struc_id(s)

        mn = "UNKNOWN"

        if sid == idaapi.BADADDR:
            return mn

        struc: idaapi.struc_t = idaapi.get_struc(sid)

        for i in range(struc.memqty):
            member: idaapi.member_t = struc.members[i]
            if off == member.get_soff():
                mn = idaapi.get_member_name(member.id)
                break
        return mn

    def walk_memptr_expr(self, e: idaapi.cexpr_t):
        base = self.walk_expr(e.x)
        off = e.m
        ptr_type: idaapi.tinfo_t = e.x.type
        struct_type: idaapi.tinfo_t = ptr_type.get_pointed_object()
        member = self.get_member_of_offset(struct_type, off)

        n = AstNode.createMemberPtrNode(e, base, member)
        return n

    def walk_memref_expr(self, e: idaapi.cexpr_t):
        base = self.walk_expr(e.x)
        off = e.m
        struct_type: idaapi.tinfo_t = e.x.type
        member = self.get_member_of_offset(struct_type, off)
        n = AstNode.createMemberPtrNode(e, base, member)
        return n

    def walk_tern_expr(self, e: idaapi.cexpr_t):
        cond = self.walk_expr(e.x)
        then = self.walk_expr(e.x)
        els = self.walk_expr(e.y)

        n = AstNode.createTernNode(e, cond, then, els)
        return n

    def walk_ptr_expr(self, e: idaapi.cexpr_t):
        v = self.walk_expr(e.x)
        r = AstNode.createStarNode(e, v)
        return r

    def walk_num_expr(self, e: idaapi.cexpr_t):

        def get_fnum_str(x):
            if hasattr(x, '_print'):
                return float(x._print())
            else:
                return float(str(x.fnum))

        if e.op == idaapi.cot_fnum:
            v: idaapi.fnumber_t = e.fpc
            num = get_fnum_str(v)
        else:
            num = e.numval()

        n = AstNode.createNumberNode(e, num)
        return n

    def walk_helper_expr(self, e: idaapi.cexpr_t):
        # print("helper: {}".format(e.helper))
        n = AstNode.createIdentifierNode(e, e.helper)
        return n

    def walk_binary_expr(self, e: idaapi.cexpr_t):
        left = self.walk_expr(e.x)
        right = self.walk_expr(e.y)

        n = AstNode.createBinaryOpNode(e, citem2str[e.op], left, right)
        return n

    def walk_idx_expr(self, e: idaapi.cexpr_t):
        array = self.walk_expr(e.x)
        idx = self.walk_expr(e.y)

        n = AstNode.createArrayIndexNode(e, array, idx)
        return n

    def walk_obj_expr(self, e: idaapi.cexpr_t):
        obj = e.obj_ea
        n = idaapi.get_name(obj).strip(".")

        tf: idaapi.tinfo_t = idaapi.tinfo_t()
        idaapi.get_tinfo(tf, obj)
        typ = tf.dstr()
        r = AstNode.createIdentifierNode(e, n, typ)
        return r

    def walk_str_expr(self, e: idaapi.cexpr_t):
        s = e.string
        r = AstNode.createStringNode(e, s)
        return r

    def walk_call_expr(self, e: idaapi.cexpr_t):
        args = []
        for a in e.a:
            args.append(self.walk_expr(a))

        target = self.walk_expr(e.x)
        r = AstNode.createCallNode(e, target, args)
        return r

    def walk_unary_expr(self, e: idaapi.cexpr_t):
        x = self.walk_expr(e.x)
        n = AstNode.createUnaryNode(e, citem2str[e.op], x)
        return n

    def walk_empty_expr(self, e: idaapi.cexpr_t):
        n = AstNode.createEmptyNode(e)
        return n

    def walk_expr(self, e: idaapi.cexpr_t):
        expr_handler = {
            idaapi.cot_idx: self.walk_idx_expr,
            idaapi.cot_fnum: self.walk_num_expr,
            idaapi.cot_num: self.walk_num_expr,
            idaapi.cot_helper: self.walk_helper_expr,
            idaapi.cot_ptr: self.walk_ptr_expr,
            idaapi.cot_call: self.walk_call_expr,
            idaapi.cot_str: self.walk_str_expr,
            idaapi.cot_obj: self.walk_obj_expr,
            idaapi.cot_var: self.walk_var_expr,
            idaapi.cot_cast: self.walk_cast_expr,

            idaapi.cot_sizeof: self.walk_sizeof_expr,

            idaapi.cot_memptr: self.walk_memptr_expr,
            idaapi.cot_memref: self.walk_memref_expr,

            idaapi.cot_tern: self.walk_tern_expr,
            idaapi.cot_empty: self.walk_empty_expr,

            # binary op
            idaapi.cot_comma: self.walk_binary_expr,
            idaapi.cot_asg: self.walk_binary_expr,
            idaapi.cot_asgbor: self.walk_binary_expr,
            idaapi.cot_asgxor: self.walk_binary_expr,
            idaapi.cot_asgband: self.walk_binary_expr,
            idaapi.cot_asgadd: self.walk_binary_expr,
            idaapi.cot_asgsub: self.walk_binary_expr,
            idaapi.cot_asgmul: self.walk_binary_expr,
            idaapi.cot_asgsshr: self.walk_binary_expr,
            idaapi.cot_asgushr: self.walk_binary_expr,
            idaapi.cot_asgshl: self.walk_binary_expr,
            idaapi.cot_asgsdiv: self.walk_binary_expr,
            idaapi.cot_asgudiv: self.walk_binary_expr,
            idaapi.cot_asgsmod: self.walk_binary_expr,
            idaapi.cot_asgumod: self.walk_binary_expr,
            idaapi.cot_lor: self.walk_binary_expr,
            idaapi.cot_land: self.walk_binary_expr,
            idaapi.cot_bor: self.walk_binary_expr,
            idaapi.cot_xor: self.walk_binary_expr,
            idaapi.cot_band: self.walk_binary_expr,
            idaapi.cot_eq: self.walk_binary_expr,
            idaapi.cot_ne: self.walk_binary_expr,
            idaapi.cot_sge: self.walk_binary_expr,
            idaapi.cot_uge: self.walk_binary_expr,
            idaapi.cot_sle: self.walk_binary_expr,
            idaapi.cot_ule: self.walk_binary_expr,
            idaapi.cot_sgt: self.walk_binary_expr,
            idaapi.cot_ugt: self.walk_binary_expr,
            idaapi.cot_slt: self.walk_binary_expr,
            idaapi.cot_ult: self.walk_binary_expr,
            idaapi.cot_sshr: self.walk_binary_expr,
            idaapi.cot_ushr: self.walk_binary_expr,
            idaapi.cot_shl: self.walk_binary_expr,
            idaapi.cot_add: self.walk_binary_expr,
            idaapi.cot_sub: self.walk_binary_expr,
            idaapi.cot_mul: self.walk_binary_expr,
            idaapi.cot_sdiv: self.walk_binary_expr,
            idaapi.cot_udiv: self.walk_binary_expr,
            idaapi.cot_smod: self.walk_binary_expr,
            idaapi.cot_umod: self.walk_binary_expr,
            idaapi.cot_fadd: self.walk_binary_expr,
            idaapi.cot_fsub: self.walk_binary_expr,
            idaapi.cot_fmul: self.walk_binary_expr,
            idaapi.cot_fdiv: self.walk_binary_expr,

            idaapi.cot_fneg: self.walk_unary_expr,
            idaapi.cot_bnot: self.walk_unary_expr,
            idaapi.cot_preinc: self.walk_unary_expr,
            idaapi.cot_postinc: self.walk_unary_expr,
            idaapi.cot_postdec: self.walk_unary_expr,
            idaapi.cot_predec: self.walk_unary_expr,
            idaapi.cot_neg: self.walk_unary_expr,
            idaapi.cot_lnot: self.walk_unary_expr,
            idaapi.cot_ref: self.walk_unary_expr,
        }

        r = {}

        if expr_handler.get(e.op):
            handler = expr_handler[e.op]
            r = handler(e)
        else:
            raise Exception("walk expr failed: {}".format(citem_to_str(e)))

        return r

    def walk_expr_insn(self, i: idaapi.cinsn_t):
        e = i.cexpr
        r = self.walk_expr(e)
        n = AstNode.createExpressionNode(i, r)
        return n

    def walk_empty(self, i: idaapi.cinsn_t):

        dummy_ctiem = fake_citem_t(i.ea, "ida2cpg_empty")
        y = AstNode.createIdentifierNode(dummy_ctiem, "ida2cpg_return_val")
        dummy_ctiem.code = "ida2cpg_empty;"
        ass = AstNode.createExpressionNode(dummy_ctiem, y)

        return ass

    def walk_continue(self, i: idaapi.cinsn_t):
        return self.walk_empty(i)

    def walk_insn(self, i):
        self.push_item(i)
        insn_handler = {
            idaapi.cit_block: self.walk_block,
            idaapi.cit_expr: self.walk_expr_insn,
            idaapi.cit_return: self.walk_return,
            idaapi.cit_if: self.walk_if,
            idaapi.cit_while: self.walk_while,
            idaapi.cit_do: self.walk_do,
            idaapi.cit_for: self.walk_for,
            idaapi.cit_goto: self.walk_goto,
            idaapi.cit_break: self.walk_break,
            idaapi.cit_switch: self.walk_switch,
            idaapi.cit_empty: self.walk_empty,
            idaapi.cit_asm: self.walk_empty,
            idaapi.cit_continue: self.walk_empty,
        }

        r = {}
        if insn_handler.get(i.op):
            handler = insn_handler[i.op]
            r = handler(i)
            if i.label_num != -1:
                l = AstNode.createLabelNode(i, i.label_num)
                r = AstNode.createBlockNode(i, [l, r])
        else:
            raise Exception("walk insn failed: {}".format(citem_to_str(i)))

        self.pop_item()

        return r


def skip_function(ea):
    n = idaapi.get_name(ea)

    if n.startswith("."):
        return True

    seg = idc.get_segm_name(ea)
    if seg in ["extern", ".plt"]:
        return True

    return False


class AstDumpThread(QtCore.QRunnable):
    def __init__(self, asts, dir, base_name, idx):
        super().__init__()
        self.dir = dir
        self.base_name = base_name
        self.asts = asts
        self.idx = idx

    def run(self):
        out = os.path.join(self.dir, "{}_{}.json".format(self.base_name, self.idx))
        print("[*] dump {}".format(out))
        d = json.dumps(self.asts, indent=2)
        with open(out, "w") as f:
            f.write(d)


if __name__ == "__main__":
    print("[*] in astdumper script!")

    idc.auto_wait()
    need_exit = False
    # print(idc.ARGV)
    if len(idc.ARGV) > 1:
        need_exit = True

    funcs = []
    input_file = idaapi.get_input_file_path()
    outdir = os.path.join(os.path.dirname(input_file), "out")
    base_name = os.path.basename(input_file)

    if not os.path.exists(outdir):
        os.mkdir(outdir)

    threadpool = QtCore.QThreadPool()

    for ea in idautils.Functions():
        if skip_function(ea):
            continue
        funcs.append(ea)

    # i = funcs.index(0x4d3d35)
    # funcs = funcs[i:]

    print("[*] total function: {}".format(len(funcs)))

    part_num = 100
    part_idx = 0

    asts = []
    for ea in funcs:
        # print("walk 0x{:x}".format(ea))
        x = AstWalkDumper()
        try:
            r = x.walk_func(ea)
            if not r:
                continue
        except Exception as e:
            x.dump_stack()
            raise e
        asts.append(r)

        if len(asts) == part_num:
            threadpool.start(AstDumpThread(asts, outdir, base_name, part_idx))
            part_idx += 1
            asts = []
            print("[*] already dump {} functions.".format(part_idx * 100))

    if len(asts) > 0:
        threadpool.start(AstDumpThread(asts, outdir, base_name, part_idx))

    print("[*] wait thread exit.")
    threadpool.waitForDone()

    print("[*] All Done!")

    if need_exit:
        idc.qexit(0)
