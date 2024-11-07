package io.joern.ida2cpg.parser

import io.joern.ida2cpg.astcreation.AstCreator
import io.joern.ida2cpg.astcreation.AstCreator.TypeConstants
import io.joern.ida2cpg.parser.Domain.HexrayAssignment.AssignTypeMap
import io.joern.ida2cpg.parser.Domain.HexrayAssignment.isAssignType
import io.joern.ida2cpg.parser.Domain.HexrayBinaryOp.BinaryOpTypeMap
import io.joern.ida2cpg.parser.Domain.HexrayBinaryOp.isBinaryOpType
import io.joern.ida2cpg.parser.Domain.HexrayUnaryOp.UnaryOpTypeMap
import io.joern.ida2cpg.parser.Domain.HexrayUnaryOp.isUnaryOpType
import io.joern.ida2cpg.parser.Domain.PhpUseType.PhpUseType
import io.joern.ida2cpg.parser.Domain.PhpUseType.getUseType
import io.shiftleft.codepropertygraph.generated.ModifierTypes
import io.shiftleft.codepropertygraph.generated.Operators
import org.slf4j.LoggerFactory
import ujson.Arr
import ujson.Obj
import ujson.Str
import ujson.Value

import scala.util.Success
import scala.util.Try

object Domain {

  object HexrayOperators {
    // TODO Decide which of these should be moved to codepropertygraph
    val coalesceOp     = "<operator>.coalesce"
    val concatOp       = "<operator>.concat"
    val identicalOp    = "<operator>.identical"
    val logicalXorOp   = "<operator>.logicalXor"
    val notIdenticalOp = "<operator>.notIdentical"
    val spaceshipOp    = "<operator>.spaceship"
    val elvisOp        = "<operator>.elvis"
    val unpack         = "<operator>.unpack"
    // Used for $array[] = $var type assignments
    val emptyArrayIdx = "<operator>.emptyArrayIdx"
    val errorSuppress = "<operator>.errorSuppress"
    // Double arrow operator used to represent key/value pairs: key => value
    val doubleArrow = "<operator>.doubleArrow"

    val assignmentCoalesceOp = "<operator>.assignmentCoalesce"
    val assignmentConcatOp   = "<operator>.assignmentConcat"

    val encaps      = "encaps"
    val declareFunc = "declare"
    val global      = "global"

    // These are handled as special cases for builtins since they have separate AST nodes in the PHP-parser output.
    val issetFunc = s"isset"
    val printFunc = s"print"
    val cloneFunc = s"clone"
    val emptyFunc = s"empty"
    val evalFunc  = s"eval"
    val exitFunc  = s"exit"
    // Used for multiple assignments for example `list($a, $b) = $someArray`
    val listFunc  = s"list"
    val isNull    = s"is_null"
    val unset     = s"unset"
    val shellExec = s"shell_exec"

    // Used for composer dependencies
    val autoload = "<autoload>"
  }

  object PhpDomainTypeConstants {
    val array  = "array"
    val bool   = "bool"
    val double = "double"
    val int    = "int"
    val obj    = "object"
    val string = "string"
    val unset  = "unset"
  }

  private val logger          = LoggerFactory.getLogger(Domain.getClass)
  val NamespaceDelimiter      = "\\"
  val StaticMethodDelimiter   = "::"
  val InstanceMethodDelimiter = "->"
  // Used for creating the default constructor.
  val ConstructorMethodName = "__construct"

  final case class HexrayAttributes(rva: Int, jsonLine: Int)

  object HexrayAttributes {
    val Empty: HexrayAttributes = HexrayAttributes(-1, -1)

    def apply(json: Value): HexrayAttributes = {
      Try(json("attributes")) match {
        case Success(Obj(attributes)) =>
          val rva        = attributes("rva").str.toInt
          val jsonLine = attributes("ea").str.toInt
          HexrayAttributes(rva, jsonLine)

        case Success(Arr(_)) =>
          logger.debug(s"Found array attributes in $json")
          HexrayAttributes.Empty

        case unhandled =>
          logger.warn(s"Could not find attributes object in type $unhandled")
          HexrayAttributes.Empty
      }
    }
  }

  object PhpModifiers {
    private val ModifierMasks = List(
      (1, ModifierTypes.PUBLIC),
      (2, ModifierTypes.PROTECTED),
      (4, ModifierTypes.PRIVATE),
      (8, ModifierTypes.STATIC),
      (16, ModifierTypes.ABSTRACT),
      (32, ModifierTypes.FINAL),
      (64, ModifierTypes.READONLY)
    )

    private val AccessModifiers: Set[String] = Set(ModifierTypes.PUBLIC, ModifierTypes.PROTECTED, ModifierTypes.PRIVATE)

    def containsAccessModifier(modifiers: List[String]): Boolean = {
      modifiers.toSet.intersect(AccessModifiers).nonEmpty
    }

    def getModifierSet(json: Value, modifierString: String = "flags"): List[String] = {
      val flags = json.objOpt.flatMap(_.get(modifierString)).map(_.num.toInt).getOrElse(0)
      ModifierMasks.collect {
        case (mask, typ) if (flags & mask) != 0 => typ
      }
    }
  }

  sealed trait HexrayNode {
    def attributes: HexrayAttributes
  }

  final case class HexrayFile(children: List[HexrayStmt]) extends HexrayNode {
    override val attributes: HexrayAttributes = HexrayAttributes.Empty
  }

  final case class HexrayParam(code: String, name: String, paramType: Option[String], attributes: HexrayAttributes)
      extends HexrayNode

  final case class HexrayLocalVariable(code: String, name: String, typ: String, attributes: HexrayAttributes)
      extends HexrayNode

  sealed trait HexrayArgument extends HexrayNode

  final case class HexrayArg(expr: HexrayExpr, parameterName: Option[String], attributes: HexrayAttributes)
      extends HexrayArgument

  object HexrayArg {
    def apply(expr: HexrayExpr): HexrayArg = {
      HexrayArg(expr, parameterName = None, attributes = expr.attributes)
    }
  }

  final case class HexrayVariadicPlaceholder(attributes: Domain.HexrayAttributes) extends HexrayArgument

  sealed trait HexrayStmt extends HexrayNode

  sealed trait HexrayStmtWithBody extends HexrayStmt {
    def stmts: List[HexrayStmt]
  }

  // In the PhpParser output, comments are included as an attribute to the first statement following the comment. If
  // no such statement exists, a Nop statement (which does not exist in PHP) is added as a sort of comment container.
  final case class NopStmt(attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayEchoStmt(exprs: Seq[HexrayExpr], attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayBreakStmt(num: Option[Int], attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayContinueStmt(num: Option[Int], attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayWhileStmt(cond: HexrayExpr, stmts: List[HexrayStmt], attributes: HexrayAttributes)
      extends HexrayStmtWithBody

  final case class HexrayBlockStmt(code: String, stmts: List[HexrayStmt], attributes: HexrayAttributes)
      extends HexrayStmtWithBody

  final case class HexrayDoStmt(cond: HexrayExpr, stmts: List[HexrayStmt], attributes: HexrayAttributes)
      extends HexrayStmtWithBody

  final case class HexrayForStmt(
    inits: HexrayExpr,
    conditions: HexrayExpr,
    loopExprs: HexrayExpr,
    stmts: List[HexrayStmt],
    attributes: HexrayAttributes
  ) extends HexrayStmtWithBody

  final case class HexrayIfStmt(
    code: String,
    cond: HexrayExpr,
    stmts: List[HexrayStmt],
    elseStmt: Option[HexrayElseStmt],
    attributes: HexrayAttributes
  ) extends HexrayStmtWithBody

  final case class HexrayElseIfStmt(cond: HexrayExpr, stmts: List[HexrayStmt], attributes: HexrayAttributes)
      extends HexrayStmtWithBody

  final case class HexrayElseStmt(stmts: List[HexrayStmt], attributes: HexrayAttributes) extends HexrayStmtWithBody

  final case class HexraySwitchStmt(
    code: String,
    condition: HexrayExpr,
    cases: List[HexrayCaseStmt],
    attributes: HexrayAttributes
  ) extends HexrayStmt

  final case class HexrayCaseStmt(condition: Seq[HexrayExpr], stmts: List[HexrayStmt], attributes: HexrayAttributes)
      extends HexrayStmtWithBody

  final case class HexrayTryStmt(
    stmts: List[HexrayStmt],
    catches: List[HexrayCatchStmt],
    finallyStmt: Option[HexrayFinallyStmt],
    attributes: HexrayAttributes
  ) extends HexrayStmtWithBody

  final case class HexrayCatchStmt(
    types: List[HeaxrayNameExpr],
    variable: Option[HexrayExpr],
    stmts: List[HexrayStmt],
    attributes: HexrayAttributes
  ) extends HexrayStmtWithBody

  final case class HexrayFinallyStmt(stmts: List[HexrayStmt], attributes: HexrayAttributes) extends HexrayStmtWithBody

  final case class HexrayReturnStmt(code: String, expr: Option[HexrayExpr], attributes: HexrayAttributes)
      extends HexrayStmt

  final case class HexrayMethodDecl(
    code: String,
    name: String,
    params: Seq[HexrayParam],
    locals: Seq[HexrayLocalVariable],
    modifiers: List[String],
    returnType: String,
    stmts: List[HexrayStmt],
    namespacedName: Option[HeaxrayNameExpr],
    isClassMethod: Boolean,
    attributes: HexrayAttributes
  ) extends HexrayStmtWithBody

  final case class PhpAttributeGroup(attrs: List[HexrayAttribute], attributes: HexrayAttributes)

  final case class HexrayAttribute(name: HeaxrayNameExpr, args: List[HexrayArgument], attributes: HexrayAttributes)
      extends HexrayExpr

  final case class HexrayClassLikeStmt(
    name: Option[HeaxrayNameExpr],
    modifiers: List[String],
    extendsNames: List[HeaxrayNameExpr],
    implementedInterfaces: List[HeaxrayNameExpr],
    stmts: List[HexrayStmt],
    classLikeType: String,
    // Optionally used for enums with values
    scalarType: Option[HeaxrayNameExpr],
    hasConstructor: Boolean,
    attributes: HexrayAttributes,
    attributeGroups: Seq[PhpAttributeGroup]
  ) extends HexrayStmtWithBody

  object ClassLikeTypes {
    val Class: String     = "class"
    val Trait: String     = "trait"
    val Interface: String = "interface"
    val Enum: String      = "enum"
  }

  final case class HexrayEnumCaseStmt(name: HeaxrayNameExpr, expr: Option[HexrayExpr], attributes: HexrayAttributes)
      extends HexrayStmt

  final case class HexrayPropertyStmt(
    modifiers: List[String],
    variables: List[HexrayPropertyValue],
    typeName: Option[HeaxrayNameExpr],
    attributes: HexrayAttributes
  ) extends HexrayStmt

  final case class HexrayPropertyValue(
    name: HeaxrayNameExpr,
    defaultValue: Option[HexrayExpr],
    attributes: HexrayAttributes
  ) extends HexrayStmt

  final case class HexrayConstStmt(
    modifiers: List[String],
    consts: List[HexrayConstDeclaration],
    attributes: HexrayAttributes
  ) extends HexrayStmt

  final case class HexrayGotoStmt(code: String, label: HeaxrayNameExpr, attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayLabelStmt(label: HeaxrayNameExpr, stmts: List[HexrayStmt], attributes: HexrayAttributes)
      extends HexrayStmt

  final case class HexrayHaltCompilerStmt(attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayConstDeclaration(
    name: HeaxrayNameExpr,
    value: HexrayExpr,
    namespacedName: Option[HeaxrayNameExpr],
    attributes: HexrayAttributes
  ) extends HexrayStmt

  final case class HexrayNamespaceStmt(
    name: Option[HeaxrayNameExpr],
    stmts: List[HexrayStmt],
    attributes: HexrayAttributes
  ) extends HexrayStmtWithBody

  final case class HexrayDeclareStmt(
    declares: Seq[HexrayDeclareItem],
    stmts: Option[List[HexrayStmt]],
    attributes: HexrayAttributes
  ) extends HexrayStmt

  final case class HexrayDeclareItem(key: HeaxrayNameExpr, value: HexrayExpr, attributes: HexrayAttributes)
      extends HexrayStmt

  final case class HexrayUnsetStmt(vars: List[HexrayExpr], attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayStaticStmt(vars: List[HexrayStaticVar], attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayStaticVar(
    variable: HexrayVariable,
    defaultValue: Option[HexrayExpr],
    attributes: HexrayAttributes
  ) extends HexrayStmt

  final case class HexrayGlobalStmt(vars: List[HexrayExpr], attributes: HexrayAttributes) extends HexrayStmt

  final case class HexrayUseStmt(uses: List[HexrayUseUse], useType: PhpUseType, attributes: HexrayAttributes)
      extends HexrayStmt

  final case class HexrayGroupUseStmt(
    prefix: HeaxrayNameExpr,
    uses: List[HexrayUseUse],
    useType: PhpUseType,
    attributes: HexrayAttributes
  ) extends HexrayStmt

  final case class HexrayUseUse(
    originalName: HeaxrayNameExpr,
    alias: Option[HeaxrayNameExpr],
    useType: PhpUseType,
    attributes: HexrayAttributes
  ) extends HexrayStmt

  case object PhpUseType {
    sealed trait PhpUseType

    case object Unknown extends PhpUseType

    case object Normal extends PhpUseType

    case object Function extends PhpUseType

    case object Constant extends PhpUseType

    def getUseType(typeNum: Int): PhpUseType = {
      typeNum match {
        case 1 => Normal
        case 2 => Function
        case 3 => Constant
        case _ => Unknown
      }
    }
  }

  final case class HexrayForeachStmt(
    iterExpr: HexrayExpr,
    keyVar: Option[HexrayExpr],
    valueVar: HexrayExpr,
    assignByRef: Boolean,
    stmts: List[HexrayStmt],
    attributes: HexrayAttributes
  ) extends HexrayStmtWithBody

  final case class HexrayTraitUseStmt(
    traits: List[HeaxrayNameExpr],
    adaptations: List[HexrayTraitUseAdaptation],
    attributes: HexrayAttributes
  ) extends HexrayStmt

  sealed trait HexrayTraitUseAdaptation extends HexrayStmt

  final case class HexrayPrecedenceAdaptation(
    traitName: HeaxrayNameExpr,
    methodName: HeaxrayNameExpr,
    insteadOf: List[HeaxrayNameExpr],
    attributes: HexrayAttributes
  ) extends HexrayTraitUseAdaptation

  final case class HexrayAliasAdaptation(
    traitName: Option[HeaxrayNameExpr],
    methodName: HeaxrayNameExpr,
    newModifier: Option[String],
    newName: Option[HeaxrayNameExpr],
    attributes: HexrayAttributes
  ) extends HexrayTraitUseAdaptation

  sealed trait HexrayExpr extends HexrayStmt

  final case class HexrayNewExpr(className: HexrayNode, args: List[HexrayArgument], attributes: HexrayAttributes)
      extends HexrayExpr

  final case class HexrayIncludeExpr(expr: HexrayExpr, includeType: String, attributes: HexrayAttributes)
      extends HexrayExpr

  case object PhpIncludeType {
    val Include: String     = "include"
    val IncludeOnce: String = "include_once"
    val Require: String     = "require"
    val RequireOnce: String = "require_once"
  }

  final case class HexrayCallExpr(
    methodName: HexrayExpr,
    args: Seq[HexrayArgument],
    code: String,
    isNullSafe: Boolean,
    isStatic: Boolean,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayVariable(value: HexrayExpr, attributes: HexrayAttributes) extends HexrayExpr

  final case class HeaxrayNameExpr(name: String, attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayCloneExpr(expr: HexrayExpr, attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayEmptyExpr(attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayCommaExpr(x: HexrayExpr, y: HexrayExpr, attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayExitExpr(expr: Option[HexrayExpr], attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayBinaryOp(
    code: String,
    operator: String,
    left: HexrayExpr,
    right: HexrayExpr,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  object HexrayBinaryOp {
    val BinaryOpTypeMap: Map[String, String] = Map(
      "cot_band"    -> Operators.and,
      "cot_bor"     -> Operators.or,
      "cot_xor"     -> Operators.xor,
      "cot_land"    -> Operators.logicalAnd,
      "cot_lor"     -> Operators.logicalOr,
      "cot_sdiv"    -> Operators.division,
      "cot_udiv"    -> Operators.division,
      "cot_fdiv"    -> Operators.division,
      "cot_fmul"    -> Operators.multiplication,
      "cot_mul"     -> Operators.multiplication,
      "cot_eq"      -> Operators.equals,
      "cot_uge"     -> Operators.greaterEqualsThan,
      "cot_sge"     -> Operators.greaterEqualsThan,
      "cot_sgt"     -> Operators.greaterThan,
      "cot_ugt"     -> Operators.greaterThan,
      "cot_sle"     -> Operators.lessEqualsThan,
      "cot_ule"     -> Operators.lessEqualsThan,
      "cot_slt"     -> Operators.lessThan,
      "cot_ult"     -> Operators.lessThan,
      "cot_ne"      -> Operators.notEquals,
      "cot_add"     -> Operators.addition,
      "cot_umod"    -> Operators.modulo,
      "cot_smod"    -> Operators.modulo,
      "cot_fadd"    -> Operators.addition,
      "cot_sub"     -> Operators.subtraction,
      "cot_fsub"    -> Operators.subtraction,
      "cot_shl"     -> Operators.shiftLeft,
      "cot_sshr"    -> Operators.arithmeticShiftRight,
      "cot_ushr"    -> Operators.arithmeticShiftRight,
      "cot_asgadd"  -> Operators.assignmentPlus,
      "cot_asgband" -> Operators.assignmentAnd,
      "cot_asgbor"  -> Operators.assignmentOr,
      "cot_asgxor"  -> Operators.assignmentXor,
      "cot_asgushr" -> Operators.assignmentArithmeticShiftRight,
      "cot_asgsshr" -> Operators.assignmentArithmeticShiftRight,
      "cot_asgshl"  -> Operators.assignmentShiftLeft,
      "cot_asgsdiv" -> Operators.assignmentDivision,
      "cot_asgudiv" -> Operators.assignmentDivision,
      "cot_asgsmod" -> Operators.assignmentModulo,
      "cot_asgumod" -> Operators.assignmentModulo,
      "cot_asgmul"  -> Operators.assignmentMultiplication,
      "cot_asgsub"  -> Operators.assignmentMinus
    )

    def isBinaryOpType(typeName: String): Boolean = {
      BinaryOpTypeMap.contains(typeName)
    }
  }

  final case class HexrayUnaryOp(code: String, operator: String, expr: HexrayExpr, attributes: HexrayAttributes)
      extends HexrayExpr

  object HexrayUnaryOp {
    val UnaryOpTypeMap: Map[String, String] = Map(
      "cot_bnot"    -> Operators.not,
      "cot_lnot"    -> Operators.logicalNot,
      "cot_postdec" -> Operators.postDecrement,
      "cot_postinc" -> Operators.postIncrement,
      "cot_predec"  -> Operators.preDecrement,
      "cot_preinc"  -> Operators.preIncrement,
      "cot_neg"     -> Operators.minus,
      "cot_fneg"    -> Operators.minus,
      "cot_ref"     -> Operators.addressOf,
      "Star"        -> Operators.indirection
    )

    def isUnaryOpType(typeName: String): Boolean = {
      UnaryOpTypeMap.contains(typeName)
    }
  }

  final case class HexrayTernaryOp(
    code: String,
    condition: HexrayExpr,
    thenExpr: HexrayExpr,
    elseExpr: HexrayExpr,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  object HexrayAssignment {
    val AssignTypeMap: Map[String, String] = Map(
      "cot_asg"                  -> Operators.assignment,
      "Expr_AssignRef"           -> Operators.assignment,
      "Expr_AssignOp_BitwiseAnd" -> Operators.assignmentAnd,
      "Expr_AssignOp_BitwiseOr"  -> Operators.assignmentOr,
      "Expr_AssignOp_BitwiseXor" -> Operators.assignmentXor,
      "Expr_AssignOp_Coalesce"   -> HexrayOperators.assignmentCoalesceOp,
      "Expr_AssignOp_Concat"     -> HexrayOperators.assignmentConcatOp,
      "Expr_AssignOp_Div"        -> Operators.assignmentDivision,
      "Expr_AssignOp_Minus"      -> Operators.assignmentMinus,
      "Expr_AssignOp_Mod"        -> Operators.assignmentModulo,
      "Expr_AssignOp_Mul"        -> Operators.assignmentMultiplication,
      "Expr_AssignOp_Plus"       -> Operators.assignmentPlus,
      "Expr_AssignOp_Pow"        -> Operators.assignmentExponentiation,
      "Expr_AssignOp_ShiftLeft"  -> Operators.assignmentShiftLeft,
      "Expr_AssignOp_ShiftRight" -> Operators.assignmentArithmeticShiftRight
    )

    def isAssignType(typeName: String): Boolean = {
      AssignTypeMap.contains(typeName)
    }
  }

  final case class HexrayAssignment(
    code: String,
    assignOp: String,
    target: HexrayExpr,
    source: HexrayExpr,
    isRefAssign: Boolean,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayCast(code: String, typ: String, expr: HexrayExpr, attributes: HexrayAttributes)
      extends HexrayExpr

  final case class HexrayIsset(vars: Seq[HexrayExpr], attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayPrint(expr: HexrayExpr, attributes: HexrayAttributes) extends HexrayExpr

  sealed trait HexrayScalar extends HexrayExpr

  sealed abstract class HexraySimpleScalar(val typeFullName: String) extends HexrayScalar {
    def value: String

    def attributes: HexrayAttributes
  }

  final case class HexrayString(val value: String, val attributes: HexrayAttributes)
      extends HexraySimpleScalar(TypeConstants.String)

  object HexrayString {
    def withQuotes(value: String, attributes: HexrayAttributes): HexrayString = {
      HexrayString(s"\"${escapeString(value)}\"", attributes)
    }
  }

  final case class HexrayInt(val value: String, val attributes: HexrayAttributes)
      extends HexraySimpleScalar(TypeConstants.Int)

  final case class HexrayFloat(val value: String, val attributes: HexrayAttributes)
      extends HexraySimpleScalar(TypeConstants.Float)

  final case class HexrayEncapsed(parts: Seq[HexrayExpr], attributes: HexrayAttributes) extends HexrayScalar

  final case class HexrayThrowExpr(expr: HexrayExpr, attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayListExpr(items: List[Option[HexrayArrayItem]], attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayClassConstFetchExpr(
    className: HexrayExpr,
    constantName: Option[HeaxrayNameExpr],
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayConstFetchExpr(name: HeaxrayNameExpr, attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayArrayExpr(items: List[Option[HexrayArrayItem]], attributes: HexrayAttributes)
      extends HexrayExpr

  final case class HexrayArrayItem(
    key: Option[HexrayExpr],
    value: HexrayExpr,
    byRef: Boolean,
    unpack: Boolean,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayArrayIndexExpr(
    code: String,
    variable: HexrayExpr,
    index: HexrayExpr,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayMemberPtrExpr(
    code: String,
    variable: HexrayExpr,
    member: HeaxrayNameExpr,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayErrorSuppressExpr(expr: HexrayExpr, attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayInstanceOfExpr(expr: HexrayExpr, className: HexrayExpr, attributes: HexrayAttributes)
      extends HexrayExpr

  final case class HexrayShellExecExpr(parts: HexrayEncapsed, attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayPropertyFetchExpr(
    expr: HexrayExpr,
    name: HexrayExpr,
    isNullsafe: Boolean,
    isStatic: Boolean,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayMatchExpr(condition: HexrayExpr, matchArms: List[HexrayMatchArm], attributes: HexrayAttributes)
      extends HexrayExpr

  final case class HexrayMatchArm(
    conditions: List[HexrayExpr],
    body: HexrayExpr,
    isDefault: Boolean,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayYieldExpr(key: Option[HexrayExpr], value: Option[HexrayExpr], attributes: HexrayAttributes)
      extends HexrayExpr

  final case class HexrayYieldFromExpr(expr: HexrayExpr, attributes: HexrayAttributes) extends HexrayExpr

  final case class HexrayClosureExpr(
    params: List[HexrayParam],
    stmts: List[HexrayStmt],
    returnType: Option[HeaxrayNameExpr],
    uses: List[HexrayClosureUse],
    isStatic: Boolean,
    returnByRef: Boolean,
    isArrowFunc: Boolean,
    attributes: HexrayAttributes
  ) extends HexrayExpr

  final case class HexrayClosureUse(variable: HexrayExpr, byRef: Boolean, attributes: HexrayAttributes)
      extends HexrayExpr

  private def escapeString(value: String): String = {
    value
      .replace("\\", "\\\\")
      .replace("\n", "\\n")
      .replace("\b", "\\b")
      .replace("\r", "\\r")
      .replace("\t", "\\t")
      .replace("\'", "\\'")
      .replace("\f", "\\f")
      .replace("\"", "\\\"")
  }

  private def readFile(json: Value): HexrayFile = {
    json match {
      case arr: Arr =>
        val children = arr.value.map(readStmt).toList
        HexrayFile(children)
      case unhandled =>
        logger.error(s"Found unhandled type in readFile: ${unhandled.getClass} with value $unhandled")
        ???
    }
  }

  private def readStmt(json: Value): HexrayStmt = {
    json("nodeType").str match {
      case "Expression" => readExpr(json("expr"))
      case "Function"   => readFunction(json)
      case "Block"      => readBlock(json)
      case "If"         => readIf(json)
      case "Return"     => readReturn(json)
      case "Goto"       => readGoto(json)
      case "Label"      => readLabel(json)
      case "While"      => readWhile(json)
      case "Do"         => readDo(json)
      case "For"        => readFor(json)
      case "Break"      => readBreak(json)
      case "Switch"     => readSwitch(json)

      case "Stmt_Continue"     => readContinue(json)
      case "Stmt_TryCatch"     => readTry(json)
      case "Stmt_Throw"        => readThrow(json)
      case "Stmt_Class"        => readClassLike(json, ClassLikeTypes.Class)
      case "Stmt_Interface"    => readClassLike(json, ClassLikeTypes.Interface)
      case "Stmt_Trait"        => readClassLike(json, ClassLikeTypes.Trait)
      case "Stmt_Enum"         => readClassLike(json, ClassLikeTypes.Enum)
      case "Stmt_EnumCase"     => readEnumCase(json)
      case "Stmt_Property"     => readProperty(json)
      case "Stmt_ClassConst"   => readConst(json)
      case "Stmt_Const"        => readConst(json)
      case "Stmt_Label"        => readLabel(json)
      case "Stmt_HaltCompiler" => readHaltCompiler(json)
      case "Stmt_Namespace"    => readNamespace(json)
      case "Stmt_Nop"          => NopStmt(HexrayAttributes(json))
      case "Stmt_Unset"        => readUnset(json)
      case "Stmt_Static"       => readStatic(json)
      case "Stmt_Global"       => readGlobal(json)
      case "Stmt_Use"          => readUse(json)
      case "Stmt_GroupUse"     => readGroupUse(json)
      case "Stmt_Foreach"      => readForeach(json)
      case "Stmt_TraitUse"     => readTraitUse(json)
      case unhandled =>
        logger.error(s"Found unhandled stmt type: $unhandled")
        ???
    }
  }

  private def readString(json: Value): HexrayString = {
    HexrayString.withQuotes(json("value").str, HexrayAttributes(json))
  }

  private def readBreakContinueNum(json: Value): Option[Int] = {
    Option.unless(json("num").isNull)(json("num")("value").toString).flatMap(_.toIntOption)
  }

  private def readBreak(json: Value): HexrayBreakStmt = {
    val num = Option(0)
    HexrayBreakStmt(num, HexrayAttributes(json))
  }

  private def readContinue(json: Value): HexrayContinueStmt = {
    val num = Option(0)
    HexrayContinueStmt(num, HexrayAttributes(json))
  }

  private def readWhile(json: Value): HexrayWhileStmt = {
    val cond  = readExpr(json("cond"))
    val stmts = readBlock(json("body"))
    HexrayWhileStmt(cond, stmts.stmts, HexrayAttributes(json))
  }

  private def readBlock(json: Value): HexrayBlockStmt = {
    val stmts = json("stmts").arr.toList.map(readStmt)
    val code  = json("code").str
    HexrayBlockStmt(code, stmts, HexrayAttributes(json))
  }

  private def readDo(json: Value): HexrayDoStmt = {
    val cond  = readExpr(json("cond"))
    val stmts = readBlock(json("body"))
    HexrayDoStmt(cond, stmts.stmts, HexrayAttributes(json))
  }

  private def readFor(json: Value): HexrayForStmt = {
    val inits      = readExpr(json("init"))
    val conditions = readExpr(json("cond"))
    val loopExprs  = readExpr(json("step"))
    val bodyStmts  = readBlock(json("body")).stmts
    HexrayForStmt(inits, conditions, loopExprs, bodyStmts, HexrayAttributes(json))
  }

  private def readIf(json: Value): HexrayIfStmt = {
    val condition = readExpr(json("cond"))
    val stmts     = json("then").arr.map(readStmt).toList
    val elseStmt  = Option.when(!json("else").isNull)(readElse(json("else")))
    var code      = json("code").str

    HexrayIfStmt(code, condition, stmts, elseStmt, HexrayAttributes(json))
  }

  private def readSwitch(json: Value): HexraySwitchStmt = {
    val condition = readExpr(json("cond"))
    val cases     = json("cases").arr.map(readCase).toList
    var code      = json("code").str
    HexraySwitchStmt(code, condition, cases, HexrayAttributes(json))
  }

  private def readTry(json: Value): HexrayTryStmt = {
    val stmts       = json("stmts").arr.map(readStmt).toList
    val catches     = json("catches").arr.map(readCatch).toList
    val finallyStmt = Option.unless(json("finally").isNull)(readFinally(json("finally")))

    HexrayTryStmt(stmts, catches, finallyStmt, HexrayAttributes(json))
  }

  private def readThrow(json: Value): HexrayThrowExpr = {
    val expr = readExpr(json("expr"))

    HexrayThrowExpr(expr, HexrayAttributes(json))
  }

  private def readList(json: Value): HexrayListExpr = {
    val items = json("items").arr.map(item => Option.unless(item.isNull)(readArrayItem(item))).toList

    HexrayListExpr(items, HexrayAttributes(json))
  }

  private def readNew(json: Value): HexrayNewExpr = {
    val classNode =
      if (json("class")("nodeType").strOpt.contains("Stmt_Class"))
        readClassLike(json("class"), ClassLikeTypes.Class)
      else
        readNameOrExpr(json, "class")

    val args = json("args").arr.map(readCallArg).toList

    HexrayNewExpr(classNode, args, HexrayAttributes(json))
  }

  private def readInclude(json: Value): HexrayIncludeExpr = {
    val expr = readExpr(json("expr"))
    val includeType = json("type").num.toInt match {
      case 1 => PhpIncludeType.Include
      case 2 => PhpIncludeType.IncludeOnce
      case 3 => PhpIncludeType.Require
      case 4 => PhpIncludeType.RequireOnce
      case other =>
        logger.warn(s"Unhandled include type: $other. Defaulting to regular include.")
        PhpIncludeType.Include
    }

    HexrayIncludeExpr(expr, includeType, HexrayAttributes(json))
  }

  private def readMatch(json: Value): HexrayMatchExpr = {
    val condition = readExpr(json("cond"))
    val matchArms = json("arms").arr.map(readMatchArm).toList

    HexrayMatchExpr(condition, matchArms, HexrayAttributes(json))
  }

  private def readMatchArm(json: Value): HexrayMatchArm = {
    val conditions = json("conds") match {
      case ujson.Null => Nil
      case conds      => conds.arr.map(readExpr).toList
    }

    val isDefault = json("conds").isNull
    val body      = readExpr(json("body"))

    HexrayMatchArm(conditions, body, isDefault, HexrayAttributes(json))
  }

  private def readYield(json: Value): HexrayYieldExpr = {
    val key   = Option.unless(json("key").isNull)(readExpr(json("key")))
    val value = Option.unless(json("value").isNull)(readExpr(json("value")))

    HexrayYieldExpr(key, value, HexrayAttributes(json))
  }

  private def readYieldFrom(json: Value): HexrayYieldFromExpr = {
    val expr = readExpr(json("expr"))

    HexrayYieldFromExpr(expr, HexrayAttributes(json))
  }

  private def readClosure(json: Value): HexrayClosureExpr = {
    val params      = json("params").arr.map(readParam).toList
    val stmts       = json("stmts").arr.map(readStmt).toList
    val returnType  = Option.unless(json("returnType").isNull)(readType(json("returnType")))
    val uses        = json("uses").arr.map(readClosureUse).toList
    val isStatic    = json("static").bool
    val isByRef     = json("byRef").bool
    val isArrowFunc = false

    HexrayClosureExpr(params, stmts, returnType, uses, isStatic, isByRef, isArrowFunc, HexrayAttributes(json))
  }

  private def readClosureUse(json: Value): HexrayClosureUse = {
    val variable = readVariable(json("var"))
    val isByRef  = json("byRef").bool

    HexrayClosureUse(variable, isByRef, HexrayAttributes(json))
  }

  private def readClassConstFetch(json: Value): HexrayClassConstFetchExpr = {
    val classNameType = json("class")("nodeType").str
    val className =
      if (classNameType.startsWith("Name"))
        readName(json("class"))
      else
        readExpr(json("class"))

    val constantName = json("name") match {
      case str: Str => Some(HeaxrayNameExpr(str.value, HexrayAttributes(json)))
      case obj: Obj if obj("nodeType").strOpt.contains("Expr_Error") => None
      case obj: Obj                                                  => Some(readName(obj))
      case other => throw new NotImplementedError(s"unexpected constant name '$other' of type ${other.getClass}")
    }

    HexrayClassConstFetchExpr(className, constantName, HexrayAttributes(json))
  }

  private def readConstFetch(json: Value): HexrayConstFetchExpr = {
    val name = readName(json("name"))

    HexrayConstFetchExpr(name, HexrayAttributes(json))
  }

  private def readArray(json: Value): HexrayArrayExpr = {
    val items = json("items").arr.map { item =>
      Option.unless(item.isNull)(readArrayItem(item))
    }.toList
    HexrayArrayExpr(items, HexrayAttributes(json))
  }

  private def readArrayItem(json: Value): HexrayArrayItem = {
    val key    = Option.unless(json("key").isNull)(readExpr(json("key")))
    val value  = readExpr(json("value"))
    val byRef  = json("byRef").bool
    val unpack = json("byRef").bool

    HexrayArrayItem(key, value, byRef, unpack, HexrayAttributes(json))
  }

  private def readArrayIndexAccess(json: Value): HexrayArrayIndexExpr = {
    val variable = readExpr(json("base"))
    val idx      = readExpr(json("index"))
    var code     = json("code").str
    HexrayArrayIndexExpr(code, variable, idx, HexrayAttributes(json))
  }

  private def readMemberPtr(json: Value): HexrayMemberPtrExpr = {
    val variable = readExpr(json("base"))
    val member   = json("member").str
    var code     = json("code").str

    val memberNode = HeaxrayNameExpr(member, HexrayAttributes.Empty)
    HexrayMemberPtrExpr(code, variable, memberNode, HexrayAttributes(json))
  }

  private def readErrorSuppress(json: Value): HexrayErrorSuppressExpr = {
    val expr = readExpr(json("expr"))
    HexrayErrorSuppressExpr(expr, HexrayAttributes(json))
  }

  private def readInstanceOf(json: Value): HexrayInstanceOfExpr = {
    val expr      = readExpr(json("expr"))
    val className = readNameOrExpr(json, "class")

    HexrayInstanceOfExpr(expr, className, HexrayAttributes(json))
  }

  private def readShellExec(json: Value): HexrayShellExecExpr = {
    val parts = readEncapsed(json)

    HexrayShellExecExpr(parts, HexrayAttributes(json))
  }

  private def readPropertyFetch(
    json: Value,
    isNullsafe: Boolean = false,
    isStatic: Boolean = false
  ): HexrayPropertyFetchExpr = {
    val expr =
      if (json.obj.contains("var"))
        readExpr(json("var"))
      else
        readNameOrExpr(json, "class")

    val name = readNameOrExpr(json, "name")

    HexrayPropertyFetchExpr(expr, name, isNullsafe, isStatic, HexrayAttributes(json))
  }

  private def readReturn(json: Value): HexrayReturnStmt = {
    val expr = Option.unless(json("expr").isNull)(readExpr(json("expr")))
    HexrayReturnStmt(json("code").str, expr, HexrayAttributes(json))
  }

  private def extendsForClassLike(json: Value): List[HeaxrayNameExpr] = {
    json.obj
      .get("extends")
      .map {
        case ujson.Null     => Nil
        case arr: ujson.Arr => arr.arr.map(readName).toList
        case obj: ujson.Obj => readName(obj) :: Nil
        case other => throw new NotImplementedError(s"unexpected 'extends' entry '$other' of type ${other.getClass}")
      }
      .getOrElse(Nil)
  }

  private def readClassLike(json: Value, classLikeType: String): HexrayClassLikeStmt = {
    val name      = Option.unless(json("name").isNull)(readName(json("name")))
    val modifiers = PhpModifiers.getModifierSet(json)

    val extendsNames = extendsForClassLike(json)

    val implements = json.obj.get("implements").map(_.arr.toList).getOrElse(Nil).map(readName)
    val stmts      = json("stmts").arr.map(readStmt).toList

    val scalarType = json.obj.get("scalarType").flatMap(typ => Option.unless(typ.isNull)(readName(typ)))

    val hasConstructor = classLikeType == ClassLikeTypes.Class

    val attributes = HexrayAttributes(json)

    val attributeGroups = json("attrGroups").arr.map(readAttributeGroup).toList

    HexrayClassLikeStmt(
      name,
      modifiers,
      extendsNames,
      implements,
      stmts,
      classLikeType,
      scalarType,
      hasConstructor,
      attributes,
      attributeGroups
    )
  }

  private def readEnumCase(json: Value): HexrayEnumCaseStmt = {
    val name = readName(json("name"))
    val expr = Option.unless(json("expr").isNull)(readExpr(json("expr")))

    HexrayEnumCaseStmt(name, expr, HexrayAttributes(json))
  }

  private def readCatch(json: Value): HexrayCatchStmt = {
    val types    = json("types").arr.map(readName).toList
    val variable = Option.unless(json("var").isNull)(readExpr(json("var")))
    val stmts    = json("stmts").arr.map(readStmt).toList

    HexrayCatchStmt(types, variable, stmts, HexrayAttributes(json))
  }

  private def readFinally(json: Value): HexrayFinallyStmt = {
    val stmts = json("stmts").arr.map(readStmt).toList

    HexrayFinallyStmt(stmts, HexrayAttributes(json))
  }

  private def readCase(json: Value): HexrayCaseStmt = {
    var values    = json.arr(0)
    var block     = json.arr(1)
    val condition = values.arr.map(x => HexrayInt(x.num.toString, HexrayAttributes.Empty)).toList
    val stmts     = readBlock(block)
    HexrayCaseStmt(condition, stmts.stmts, HexrayAttributes.Empty)
  }

  private def readElseIf(json: Value): HexrayElseIfStmt = {
    val condition = readExpr(json("cond"))
    val stmts     = json("stmts").arr.map(readStmt).toList

    HexrayElseIfStmt(condition, stmts, HexrayAttributes(json))
  }

  private def readElse(json: Value): HexrayElseStmt = {
    val stmts = json.arr.map(readStmt).toList

    HexrayElseStmt(stmts, HexrayAttributes.Empty)
  }

  private def readEncapsed(json: Value): HexrayEncapsed = {
    HexrayEncapsed(json("parts").arr.map(readExpr).toSeq, HexrayAttributes(json))
  }

  private def readMagicConst(json: Value): HexrayConstFetchExpr = {
    val name = json("nodeType").str match {
      case "Scalar_MagicConst_Class"     => "__CLASS__"
      case "Scalar_MagicConst_Dir"       => "__DIR__"
      case "Scalar_MagicConst_File"      => "__FILE__"
      case "Scalar_MagicConst_Function"  => "__FUNCTION__"
      case "Scalar_MagicConst_Line"      => "__LINE__"
      case "Scalar_MagicConst_Method"    => "__METHOD__"
      case "Scalar_MagicConst_Namespace" => "__NAMESPACE__"
      case "Scalar_MagicConst_Trait"     => "__TRAIT__"
    }

    val attributes = HexrayAttributes(json)
    HexrayConstFetchExpr(HeaxrayNameExpr(name, attributes), attributes)
  }

  private def readExpr(json: Value): HexrayExpr = {
    json("nodeType").str match {
      case "String"                    => readString(json)
      case "Number"                    => HexrayInt(json("value").toString, HexrayAttributes(json))
      case "Scalar_Encapsed"           => readEncapsed(json)
      case "Scalar_InterpolatedString" => readEncapsed(json)
      case "Scalar_EncapsedStringPart" => readString(json)
      case "InterpolatedStringPart"    => readString(json)

      case "Call"             => readCall(json)
      case "ArrayIndexAccess" => readArrayIndexAccess(json)
      case "MemberPtr"        => readMemberPtr(json)
      case "Tern"             => readTernaryOp(json)
      case "Empty"            => readEmpty(json)
      case "cot_comma"        => readComma(json)

      case "Expr_Clone"     => readClone(json)
      case "Expr_Exit"      => readExit(json)
      case "Identifier"     => readVariable(json)
      case "Expr_Isset"     => readIsset(json)
      case "Expr_Print"     => readPrint(json)
      case "Expr_Throw"     => readThrow(json)
      case "Expr_List"      => readList(json)
      case "Expr_New"       => readNew(json)
      case "Expr_Include"   => readInclude(json)
      case "Expr_Match"     => readMatch(json)
      case "Expr_Yield"     => readYield(json)
      case "Expr_YieldFrom" => readYieldFrom(json)
      case "Expr_Closure"   => readClosure(json)

      case "Expr_ClassConstFetch" => readClassConstFetch(json)
      case "Expr_ConstFetch"      => readConstFetch(json)

      case "Expr_Array" => readArray(json)

      case "Expr_ErrorSuppress" => readErrorSuppress(json)
      case "Expr_Instanceof"    => readInstanceOf(json)
      case "Expr_ShellExec"     => readShellExec(json)

      case "Expr_PropertyFetch"         => readPropertyFetch(json)
      case "Expr_NullsafePropertyFetch" => readPropertyFetch(json, isNullsafe = true)
      case "Expr_StaticPropertyFetch"   => readPropertyFetch(json, isStatic = true)
      case "Cast"                       => readCast(json)
      case typ if isUnaryOpType(typ)    => readUnaryOp(json)
      case typ if isBinaryOpType(typ)   => readBinaryOp(json)
      case typ if isAssignType(typ)     => readAssign(json)

      case unhandled =>
        logger.error(s"Found unhandled expr type: $unhandled")
        ???
    }
  }

  private def readClone(json: Value): HexrayCloneExpr = {
    val expr = readExpr(json("expr"))
    HexrayCloneExpr(expr, HexrayAttributes(json))
  }

  private def readEmpty(json: Value): HexrayEmptyExpr = {
    HexrayEmptyExpr(HexrayAttributes(json))
  }

  private def readComma(json: Value): HexrayCommaExpr = {
    val x = readExpr(json("left"))
    val y = readExpr(json("right"))
    HexrayCommaExpr(x, y, HexrayAttributes(json))
  }

  private def readExit(json: Value): HexrayExitExpr = {
    val expr = Option.unless(json("expr").isNull)(readExpr(json("expr")))
    HexrayExitExpr(expr, HexrayAttributes(json))
  }

  private def readVariable(json: Value): HexrayVariable = {
    if (!json.obj.contains("name")) {
      logger.error(s"Variable did not contain name: $json")
    }
    val varAttrs = HexrayAttributes(json)
    val name = json("name") match {
      case Str(value) => readName(value).copy(attributes = varAttrs)
      case Obj(_)     => readNameOrExpr(json, "name")
      case value      => readExpr(value)
    }
    HexrayVariable(name, varAttrs)
  }

  private def readIsset(json: Value): HexrayIsset = {
    val vars = json("vars").arr.map(readExpr).toList
    HexrayIsset(vars, HexrayAttributes(json))
  }

  private def readPrint(json: Value): HexrayPrint = {
    val expr = readExpr(json("expr"))
    HexrayPrint(expr, HexrayAttributes(json))
  }

  private def readTernaryOp(json: Value): HexrayTernaryOp = {
    val condition     = readExpr(json("cond"))
    val maybeThenExpr = readExpr(json("if"))
    val elseExpr      = readExpr(json("else"))
    val code          = json("code").str

    HexrayTernaryOp(code, condition, maybeThenExpr, elseExpr, HexrayAttributes(json))
  }

  private def readNameOrExpr(json: Value, fieldName: String): HexrayExpr = {
    val field = json(fieldName)
    if (field("nodeType").str.startsWith("Name"))
      readName(field)
    else if (field("nodeType").str == "Identifier")
      readName(field)
    else if (field("nodeType").str == "VarLikeIdentifier") {
      readVariable(field)
    } else
      readExpr(field)
  }

  private def readCall(json: Value): HexrayCallExpr = {
    val jsonMap  = json.obj
    val nodeType = json("nodeType").str
    val args     = json("args").arr.map(readCallArg).toSeq
    var code     = json("code").str

    val methodName = readNameOrExpr(json, "name")
    HexrayCallExpr(methodName, args, code, false, true, HexrayAttributes(json))
  }

  private def readFunction(json: Value): HexrayMethodDecl = {
    val name       = json("name").str
    val code       = json("code").str
    val params     = json("paramters").arr.map(readParam).toList
    val localDecls = json("localDecls").arr.map(readLocalDecl).toList
    val returnType = json("returnType").toString
    val stmts      = json("body").arr.map(readStmt).toList
    // Only class methods have modifiers
    val modifiers      = Nil
    val namespacedName = Option.unless(json("namespacedName").isNull)(readName(json("namespacedName")))
    val isClassMethod  = false

    HexrayMethodDecl(
      code,
      name,
      params,
      localDecls,
      modifiers,
      returnType,
      stmts,
      namespacedName,
      isClassMethod,
      HexrayAttributes(json)
    )
  }

  private def readAttributeGroup(json: Value): PhpAttributeGroup = {
    PhpAttributeGroup(json("attrs").arr.map(readAttribute).toList, HexrayAttributes(json))
  }

  private def readAttribute(json: Value): HexrayAttribute = {
    HexrayAttribute(readName(json("name")), json("args").arr.map(readCallArg).toList, HexrayAttributes(json))
  }

  private def readProperty(json: Value): HexrayPropertyStmt = {
    val modifiers = PhpModifiers.getModifierSet(json)
    val variables = json("props").arr.map(readPropertyValue).toList
    val typeName  = Option.unless(json("type").isNull)(readType(json("type")))

    HexrayPropertyStmt(modifiers, variables, typeName, HexrayAttributes(json))
  }

  private def readPropertyValue(json: Value): HexrayPropertyValue = {
    val name         = readName(json("name"))
    val defaultValue = Option.unless(json("default").isNull)(readExpr(json("default")))

    HexrayPropertyValue(name, defaultValue, HexrayAttributes(json))
  }

  private def readConst(json: Value): HexrayConstStmt = {
    val modifiers = PhpModifiers.getModifierSet(json)

    val constDeclarations = json("consts").arr.map(readConstDeclaration).toList

    HexrayConstStmt(modifiers, constDeclarations, HexrayAttributes(json))
  }

  private def readGoto(json: Value): HexrayGotoStmt = {
    val code = json("code").str

    val ea        = json("target")("ea").str.toInt
    val treeindex = json("target")("treeindex").str.toInt
    var label     = json("label")("name").str

    HexrayGotoStmt(code, HeaxrayNameExpr(label, HexrayAttributes(ea, treeindex)), HexrayAttributes(json))
  }

  private def readLabel(json: Value): HexrayLabelStmt = {
    val name  = readName(json("expr")("name"))
    val stmts = json("stmts")("stmts").arr.toList.map(readStmt)
    HexrayLabelStmt(name, stmts, HexrayAttributes(json))
  }

  private def readHaltCompiler(json: Value): HexrayHaltCompilerStmt = {
    // Ignore the remaining text here since it can get quite large (common use case is to separate code from data blob)
    HexrayHaltCompilerStmt(HexrayAttributes(json))
  }

  private def readNamespace(json: Value): HexrayNamespaceStmt = {
    val name = Option.unless(json("name").isNull)(readName(json("name")))

    val stmts = json("stmts") match {
      case ujson.Null => Nil
      case stmts: Arr => stmts.arr.map(readStmt).toList
      case unhandled =>
        logger.warn(s"Unhandled namespace stmts type $unhandled")
        ???
    }

    HexrayNamespaceStmt(name, stmts, HexrayAttributes(json))
  }

  private def readLocalDecl(json: Value): HexrayLocalVariable = {
    val typ  = json("type").str
    var code = json("code").str
    var name = json("name").str
    HexrayLocalVariable(code = code, name = name, typ = typ, attributes = HexrayAttributes(json))
  }

  private def readUnset(json: Value): HexrayUnsetStmt = {
    val vars = json("vars").arr.map(readExpr).toList

    HexrayUnsetStmt(vars, HexrayAttributes(json))
  }

  private def readStatic(json: Value): HexrayStaticStmt = {
    val vars = json("vars").arr.map(readStaticVar).toList

    HexrayStaticStmt(vars, HexrayAttributes(json))
  }

  private def readGlobal(json: Value): HexrayGlobalStmt = {
    val vars = json("vars").arr.map(readExpr).toList

    HexrayGlobalStmt(vars, HexrayAttributes(json))
  }

  private def readUse(json: Value): HexrayUseStmt = {
    val useType = getUseType(json("type").num.toInt)
    val uses    = json("uses").arr.map(readUseUse(_, useType)).toList

    HexrayUseStmt(uses, useType, HexrayAttributes(json))
  }

  private def readGroupUse(json: Value): HexrayGroupUseStmt = {
    val prefix  = readName(json("prefix"))
    val useType = getUseType(json("type").num.toInt)
    val uses    = json("uses").arr.map(readUseUse(_, useType)).toList

    HexrayGroupUseStmt(prefix, uses, useType, HexrayAttributes(json))
  }

  private def readForeach(json: Value): HexrayForeachStmt = {
    val iterExpr    = readExpr(json("expr"))
    val keyVar      = Option.unless(json("keyVar").isNull)(readExpr(json("keyVar")))
    val valueVar    = readExpr(json("valueVar"))
    val assignByRef = json("byRef").bool
    val stmts       = json("stmts").arr.map(readStmt).toList

    HexrayForeachStmt(iterExpr, keyVar, valueVar, assignByRef, stmts, HexrayAttributes(json))
  }

  private def readTraitUse(json: Value): HexrayTraitUseStmt = {
    val traits      = json("traits").arr.map(readName).toList
    val adaptations = json("adaptations").arr.map(readTraitUseAdaptation).toList
    HexrayTraitUseStmt(traits, adaptations, HexrayAttributes(json))
  }

  private def readTraitUseAdaptation(json: Value): HexrayTraitUseAdaptation = {
    json("nodeType").str match {
      case "Stmt_TraitUseAdaptation_Alias"      => readAliasAdaptation(json)
      case "Stmt_TraitUseAdaptation_Precedence" => readPrecedenceAdaptation(json)
    }
  }

  private def readAliasAdaptation(json: Value): HexrayAliasAdaptation = {
    val traitName  = Option.unless(json("trait").isNull)(readName(json("trait")))
    val methodName = readName(json("method"))
    val newName    = Option.unless(json("newName").isNull)(readName(json("newName")))

    val newModifier = json("newModifier") match {
      case ujson.Null => None
      case _          => PhpModifiers.getModifierSet(json, "newModifier").headOption
    }
    HexrayAliasAdaptation(traitName, methodName, newModifier, newName, HexrayAttributes(json))
  }

  private def readPrecedenceAdaptation(json: Value): HexrayPrecedenceAdaptation = {
    val traitName  = readName(json("trait"))
    val methodName = readName(json("method"))
    val insteadOf  = json("insteadof").arr.map(readName).toList

    HexrayPrecedenceAdaptation(traitName, methodName, insteadOf, HexrayAttributes(json))
  }

  private def readUseUse(json: Value, parentType: PhpUseType): HexrayUseUse = {
    val name  = readName(json("name"))
    val alias = Option.unless(json("alias").isNull)(readName(json("alias")))
    val useType =
      if (parentType == PhpUseType.Unknown)
        getUseType(json("type").num.toInt)
      else
        parentType

    HexrayUseUse(name, alias, useType, HexrayAttributes(json))
  }

  private def readStaticVar(json: Value): HexrayStaticVar = {
    val variable     = readVariable(json("var"))
    val defaultValue = Option.unless(json("default").isNull)(readExpr(json("default")))

    HexrayStaticVar(variable, defaultValue, HexrayAttributes(json))
  }

  private def readDeclareItem(json: Value): HexrayDeclareItem = {
    val key   = readName(json("key"))
    val value = readExpr(json("value"))

    HexrayDeclareItem(key, value, HexrayAttributes(json))
  }

  private def readConstDeclaration(json: Value): HexrayConstDeclaration = {
    val name           = readName(json("name"))
    val value          = readExpr(json("value"))
    val namespacedName = Option.unless(json("namespacedName").isNull)(readName(json("namespacedName")))

    HexrayConstDeclaration(name, value, namespacedName, HexrayAttributes(json))
  }

  private def readParam(json: Value): HexrayParam = {
    val paramType = Option.unless(json("type").isNull)(json("type").toString)
    var code      = json("code").str
    HexrayParam(code = code, name = json("name").str, paramType = paramType, attributes = HexrayAttributes(json))
  }

  private def readName(json: Value): HeaxrayNameExpr = {
    json match {
      case Str(name) => HeaxrayNameExpr(name, HexrayAttributes.Empty)

      case Obj(value) if value.get("nodeType").map(_.str).contains("Name_FullyQualified") =>
        val name = value("parts").arr.map(_.str).mkString(NamespaceDelimiter)
        HeaxrayNameExpr(name, HexrayAttributes(json))

      case Obj(value) if value.get("nodeType").map(_.str).contains("Name") =>
        // TODO Can this case just be merged with Name_FullyQualified?
        val name = value("parts").arr.map(_.str).mkString(NamespaceDelimiter)
        HeaxrayNameExpr(name, HexrayAttributes(json))

      case Obj(value) if value.get("nodeType").map(_.str).contains("Identifier") =>
        val name = value("name").str
        HeaxrayNameExpr(name, HexrayAttributes(json))

      case Obj(value) if value.get("nodeType").map(_.str).contains("VarLikeIdentifier") =>
        val name = value("name").str
        HeaxrayNameExpr(name, HexrayAttributes(json))

      case unhandled =>
        logger.error(s"Found unhandled name type $unhandled: $json")
        ??? // TODO: other matches are possible?
    }
  }

  /** One of Identifier, Name, or Complex Type (Nullable, Intersection, or Union)
    */
  private def readType(json: Value): HeaxrayNameExpr = {
    json match {
      case Obj(value) if value.get("nodeType").map(_.str).contains("NullableType") =>
        val containedName = readType(value("type")).name
        HeaxrayNameExpr(s"?$containedName", attributes = HexrayAttributes(json))

      case Obj(value) if value.get("nodeType").map(_.str).contains("IntersectionType") =>
        val names = value("types").arr.map(readName).map(_.name)
        HeaxrayNameExpr(names.mkString("&"), HexrayAttributes(json))

      case Obj(value) if value.get("nodeType").map(_.str).contains("UnionType") =>
        val names = value("types").arr.map(readType).map(_.name)
        HeaxrayNameExpr(names.mkString("|"), HexrayAttributes(json))

      case other => readName(other)
    }
  }

  private def readUnaryOp(json: Value): HexrayUnaryOp = {
    val opType = UnaryOpTypeMap(json("nodeType").str)
    val expr   = readExpr(json.obj("expr"))
    HexrayUnaryOp(json.obj("code").str, opType, expr, HexrayAttributes(json))
  }

  private def readBinaryOp(json: Value): HexrayBinaryOp = {
    val opType = BinaryOpTypeMap(json("nodeType").str)

    val leftExpr  = readExpr(json("left"))
    val rightExpr = readExpr(json("right"))

    HexrayBinaryOp(json.obj("code").str, opType, leftExpr, rightExpr, HexrayAttributes(json))
  }

  private def readAssign(json: Value): HexrayAssignment = {
    val nodeType = json("nodeType").str
    val opType   = AssignTypeMap(nodeType)

    val target = readExpr(json("left"))
    val source = readExpr(json("right"))

    val isRefAssign = nodeType == "Expr_AssignRef"

    HexrayAssignment(json("code").str, opType, target, source, isRefAssign, HexrayAttributes(json))
  }

  private def readCast(json: Value): HexrayCast = {
    val expr = readExpr(json("expr"))
    val typ  = json("type").str
    val code = json("code").str
    var c    = s"(${typ})${code}"
    HexrayCast(c, typ, expr, HexrayAttributes(json))
  }

  private def readCallArg(json: Value): HexrayArgument = {
    HexrayArg(expr = readExpr(json), parameterName = Option(json("code").str), attributes = HexrayAttributes(json))

  }

  def fromJson(jsonInput: Value): HexrayFile = {
    readFile(jsonInput)
  }
}
