package io.joern.ida2cpg.astcreation

import io.joern.ida2cpg.astcreation.AstCreator.{NameConstants, TypeConstants, operatorSymbols}
import io.joern.ida2cpg.datastructures.ArrayIndexTracker
import io.joern.ida2cpg.parser.Domain.*
import io.joern.ida2cpg.parser.Domain.PhpModifiers.containsAccessModifier
import io.joern.ida2cpg.utils.Scope
import io.joern.x2cpg.Ast.storeInDiffGraph
import io.joern.x2cpg.Defines.{StaticInitMethodName, UnresolvedNamespace, UnresolvedSignature}
import io.joern.x2cpg.datastructures.Global
import io.joern.x2cpg.utils.AstPropertiesUtil.RootProperties
import io.joern.x2cpg.utils.NodeBuilders.*
import io.joern.x2cpg.{Ast, AstCreatorBase, AstNodeBuilder, ValidationMode}
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.IntervalKeyPool
import io.shiftleft.semanticcpg.language.types.structure.NamespaceTraversal
import org.slf4j.LoggerFactory
import overflowdb.BatchedUpdate

import java.nio.charset.StandardCharsets
import scala.collection.mutable

class AstCreator(filename: String, hexrayFile: HexrayFile, fileContent: Option[String], val global: Global)(implicit
  withSchemaValidation: ValidationMode
) extends AstCreatorBase(filename)
    with AstNodeBuilder[HexrayNode, AstCreator] {

  private val logger          = LoggerFactory.getLogger(AstCreator.getClass)
  private val scope           = new Scope()(() => nextClosureName())
  private val tmpKeyPool      = new IntervalKeyPool(first = 0, last = Long.MaxValue)
  private val globalNamespace = globalNamespaceBlock()

  private def getNewTmpName(prefix: String = "tmp"): String = s"$prefix${tmpKeyPool.next.toString}"

  override def createAst(): BatchedUpdate.DiffGraphBuilder = {
    val ast = astForHexrayFile(hexrayFile)
    storeInDiffGraph(ast, diffGraph)
    diffGraph
  }

  private def flattenGlobalNamespaceStmt(stmt: HexrayStmt): List[HexrayStmt] = {
    stmt match {
      case namespace: HexrayNamespaceStmt if namespace.name.isEmpty =>
        namespace.stmts

      case _ => stmt :: Nil
    }
  }

  private def globalTypeDeclNode(file: HexrayFile, globalNamespace: NewNamespaceBlock): NewTypeDecl = {
    typeDeclNode(
      file,
      globalNamespace.name,
      globalNamespace.fullName,
      filename,
      globalNamespace.code,
      NodeTypes.NAMESPACE_BLOCK,
      globalNamespace.fullName
    )
  }

  protected def registerType(typeName: String): String = {
    val fixedTypeName = typeName
    global.usedTypes.putIfAbsent(fixedTypeName, true)
    fixedTypeName
  }

  private def globalMethodDeclStmt(file: HexrayFile, bodyStmts: List[HexrayStmt]): HexrayMethodDecl = {
    val modifiersList = List(ModifierTypes.VIRTUAL, ModifierTypes.PUBLIC, ModifierTypes.STATIC, ModifierTypes.MODULE)
    HexrayMethodDecl(
      code = "<placehole>",
      name = NamespaceTraversal.globalNamespaceName,
      params = Nil,
      locals = Nil,
      modifiers = modifiersList,
      returnType = "None",
      stmts = bodyStmts,
      namespacedName = None,
      isClassMethod = false,
      attributes = file.attributes
    )
  }

  private def astForHexrayFile(file: HexrayFile): Ast = {
    val fileNode = NewFile().name(filename)
    fileContent.foreach(fileNode.content(_))

    scope.pushNewScope(globalNamespace)

    val (globalDeclStmts, globalMethodStmts) =
      file.children.flatMap(flattenGlobalNamespaceStmt).partition(_.isInstanceOf[HexrayConstStmt])

    val globalMethodStmt = globalMethodDeclStmt(file, globalMethodStmts)

    val globalTypeDeclStmt = HexrayClassLikeStmt(
      name = Some(HeaxrayNameExpr(globalNamespace.name, file.attributes)),
      modifiers = Nil,
      extendsNames = Nil,
      implementedInterfaces = Nil,
      stmts = globalDeclStmts.appended(globalMethodStmt),
      classLikeType = ClassLikeTypes.Class,
      scalarType = None,
      hasConstructor = false,
      attributes = file.attributes,
      Seq.empty[PhpAttributeGroup]
    )

    val globalTypeDeclAst = astForClassLikeStmt(globalTypeDeclStmt)

    scope.popScope() // globalNamespace

    Ast(fileNode).withChild(Ast(globalNamespace).withChild(globalTypeDeclAst))
  }

  private def astsForStmt(stmt: HexrayStmt): List[Ast] = {
    stmt match {
      case expr: HexrayExpr => astForExpr(expr) :: Nil

      case methodDecl: HexrayMethodDecl       => astForMethodDecl(methodDecl) :: Nil
      case breakStmt: HexrayBreakStmt         => astForBreakStmt(breakStmt) :: Nil
      case contStmt: HexrayContinueStmt       => astForContinueStmt(contStmt) :: Nil
      case blockStmt: HexrayBlockStmt         => astForBlockStmt(blockStmt) :: Nil
      case whileStmt: HexrayWhileStmt         => astForWhileStmt(whileStmt) :: Nil
      case doStmt: HexrayDoStmt               => astForDoStmt(doStmt) :: Nil
      case forStmt: HexrayForStmt             => astForForStmt(forStmt) :: Nil
      case ifStmt: HexrayIfStmt               => astForIfStmt(ifStmt) :: Nil
      case switchStmt: HexraySwitchStmt       => astForSwitchStmt(switchStmt) :: Nil
      case tryStmt: HexrayTryStmt             => astForTryStmt(tryStmt) :: Nil
      case returnStmt: HexrayReturnStmt       => astForReturnStmt(returnStmt) :: Nil
      case classLikeStmt: HexrayClassLikeStmt => astForClassLikeStmt(classLikeStmt) :: Nil
      case gotoStmt: HexrayGotoStmt           => astForGotoStmt(gotoStmt) :: Nil
      case labelStmt: HexrayLabelStmt         => astForLabelStmt(labelStmt) :: Nil
      case namespace: HexrayNamespaceStmt     => astForNamespaceStmt(namespace) :: Nil
      case declareStmt: HexrayDeclareStmt     => astForDeclareStmt(declareStmt) :: Nil
      case _: NopStmt                         => Nil // TODO This'll need to be updated when comments are added.
      case haltStmt: HexrayHaltCompilerStmt   => astForHaltCompilerStmt(haltStmt) :: Nil
      case unsetStmt: HexrayUnsetStmt         => astForUnsetStmt(unsetStmt) :: Nil
      case globalStmt: HexrayGlobalStmt       => astForGlobalStmt(globalStmt) :: Nil
      case useStmt: HexrayUseStmt             => astForUseStmt(useStmt) :: Nil
      case groupUseStmt: HexrayGroupUseStmt   => astForGroupUseStmt(groupUseStmt) :: Nil
      case foreachStmt: HexrayForeachStmt     => astForForeachStmt(foreachStmt) :: Nil
      case traitUseStmt: HexrayTraitUseStmt   => astforTraitUseStmt(traitUseStmt) :: Nil
      case enumCase: HexrayEnumCaseStmt       => astForEnumCase(enumCase) :: Nil
      case staticStmt: HexrayStaticStmt       => astsForStaticStmt(staticStmt)
      case unhandled =>
        logger.error(s"Unhandled stmt $unhandled in $filename")
        ???
    }
  }

  private def thisParamAstForMethod(originNode: HexrayNode): Ast = {
    val typeFullName = scope.getEnclosingTypeDeclTypeFullName.getOrElse(TypeConstants.Any)

    val thisNode = parameterInNode(
      originNode,
      name = NameConstants.This,
      code = NameConstants.This,
      index = 0,
      isVariadic = false,
      evaluationStrategy = EvaluationStrategies.BY_SHARING,
      typeFullName = typeFullName
    ).dynamicTypeHintFullName(typeFullName :: Nil)
    // TODO Add dynamicTypeHintFullName to parameterInNode param list

    scope.addToScope(NameConstants.This, thisNode)

    Ast(thisNode)
  }

  private def thisIdentifier(lineNumber: Option[Integer]): NewIdentifier = {
    val typ = scope.getEnclosingTypeDeclTypeName
    newIdentifierNode(NameConstants.This, typ.getOrElse("ANY"), typ.toList, lineNumber)
      .code(s"$$${NameConstants.This}")
  }

  private def setParamIndices(asts: Seq[Ast]): Seq[Ast] = {
    asts.map(_.root).zipWithIndex.foreach {
      case (Some(root: NewMethodParameterIn), idx) =>
        root.index(idx + 1)

      case (root, _) =>
        logger.warn(s"Trying to set index for unsupported node $root")
    }

    asts
  }

  private def composeMethodFullName(methodName: String, isStatic: Boolean): String = {
    if (methodName == NamespaceTraversal.globalNamespaceName) {
      globalNamespace.fullName
    } else {
      val className       = getTypeDeclPrefix
      val methodDelimiter = if (isStatic) StaticMethodDelimiter else InstanceMethodDelimiter

      val nameWithClass = List(className, Some(methodName)).flatten.mkString(methodDelimiter)

      prependNamespacePrefix(nameWithClass)
    }
  }

  private def astForMethodDecl(
    decl: HexrayMethodDecl,
    bodyPrefixAsts: List[Ast] = Nil,
    fullNameOverride: Option[String] = None,
    isConstructor: Boolean = false
  ): Ast = {
    val isStatic = decl.modifiers.contains(ModifierTypes.STATIC)

    val methodName = decl.name
    val fullName   = fullNameOverride.getOrElse(composeMethodFullName(methodName, isStatic))

    val signature = s"$UnresolvedSignature(${decl.params.size})"

    val constructorModifier   = Option.when(isConstructor)(ModifierTypes.CONSTRUCTOR)
    val defaultAccessModifier = Option.unless(containsAccessModifier(decl.modifiers))(ModifierTypes.PUBLIC)

    val allModifiers   = constructorModifier ++: defaultAccessModifier ++: decl.modifiers
    val modifiers      = allModifiers.map(newModifierNode)
    val modifierString = ""
    val methodCode     = decl.code
    val returnType     = decl.returnType

    val method = methodNode(decl, methodName, methodCode, fullName, Some(signature), filename)
    scope.pushNewScope(method)

    val parameters = decl.params.zipWithIndex.map { case (param, idx) =>
      astForParam(param, idx + 1)
    }
    var locals = decl.locals.map(astForLocal)

    val methodBodyStmts = bodyPrefixAsts ++ decl.stmts.flatMap(astsForStmt)
    val methodReturn    = newMethodReturnNode(returnType, line = line(decl), column = None)

    val methodBody = blockAst(blockNode(decl), methodBodyStmts)
    scope.popScope()
    methodAstWithAnnotations(method, parameters ++ locals, methodBody, methodReturn, modifiers)
  }

  private def astForAttributeGroup(attrGrp: PhpAttributeGroup): Seq[Ast] = {
    attrGrp.attrs.map(astForAttribute)
  }

  private def astForAttribute(attribute: HexrayAttribute): Ast = {
    val name     = attribute.name
    val fullName = composeMethodFullName(name.name, true)
    val _annotationNode =
      annotationNode(attribute, code = name.name, attribute.name.name, fullName)
    val argsAst = attribute.args.map(astForCallArg)
    annotationAst(_annotationNode, argsAst)
  }

  private def stmtBodyBlockAst(stmt: HexrayStmtWithBody): Ast = {
    val bodyBlock    = blockNode(stmt)
    val bodyStmtAsts = stmt.stmts.flatMap(astsForStmt)
    Ast(bodyBlock).withChildren(bodyStmtAsts)
  }

  private def astForParam(param: HexrayParam, index: Int): Ast = {
    val evaluationStrategy = EvaluationStrategies.BY_VALUE

    val typeFullName = param.paramType

    val byRefCodePrefix = ""
    val code            = param.code
    val paramNode       = parameterInNode(param, param.name, code, index, false, evaluationStrategy, typeFullName)

    scope.addToScope(param.name, paramNode)
    Ast(paramNode)
  }

  private def astForLocal(local: HexrayLocalVariable): Ast = {
    val evaluationStrategy = EvaluationStrategies.BY_VALUE

    val tpe  = registerType(local.typ)
    val node = localNode(local, local.name, local.code, tpe)

    scope.addToScope(node.name, node)
    Ast(node)
  }

  private def astForTernaryOp(ternaryOp: HexrayTernaryOp): Ast = {
    val conditionAst = astForExpr(ternaryOp.condition)
    val maybeThenAst = astForExpr(ternaryOp.thenExpr)
    val elseAst      = astForExpr(ternaryOp.elseExpr)

    val operatorName = Operators.conditional
    val code         = ternaryOp.code
    val callNode     = newOperatorCallNode(operatorName, code, line = line(ternaryOp))

    val args = List(Option(conditionAst), Option(maybeThenAst), Option(elseAst)).flatten
    callAst(callNode, args)
  }

  private def astForExpr(expr: HexrayExpr): Ast = {
    expr match {
      case funcCallExpr: HexrayCallExpr => astForCall(funcCallExpr)
      case variableExpr: HexrayVariable => astForVariableExpr(variableExpr)
      case nameExpr: HeaxrayNameExpr    => astForNameExpr(nameExpr)
      case assignExpr: HexrayAssignment => astForAssignment(assignExpr)
      case scalarExpr: HexrayScalar     => astForScalar(scalarExpr)
      case binaryOp: HexrayBinaryOp     => astForBinOp(binaryOp)
      case unaryOp: HexrayUnaryOp       => astForUnaryOp(unaryOp)
      case castExpr: HexrayCast         => astForCastExpr(castExpr)
      case isSetExpr: HexrayIsset       => astForIsSetExpr(isSetExpr)

      case memberPtrExpr: HexrayMemberPtrExpr   => astForMemberPtrExpr(memberPtrExpr)
      case arrayIndexExpr: HexrayArrayIndexExpr => astForArrayIndexExpr(arrayIndexExpr)
      case ternaryOp: HexrayTernaryOp           => astForTernaryOp(ternaryOp)

      case emptyExpr: HexrayEmptyExpr => astForEmpty(emptyExpr)
      case commaExpr: HexrayCommaExpr => astForCommaExpr(commaExpr)

      // -----
      case arrayExpr: HexrayArrayExpr                     => astForArrayExpr(arrayExpr)
      case listExpr: HexrayListExpr                       => astForListExpr(listExpr)
      case matchExpr: HexrayMatchExpr                     => astForMatchExpr(matchExpr)
      case yieldExpr: HexrayYieldExpr                     => astForYieldExpr(yieldExpr)
      case classConstFetchExpr: HexrayClassConstFetchExpr => astForClassConstFetchExpr(classConstFetchExpr)
      case constFetchExpr: HexrayConstFetchExpr           => astForConstFetchExpr(constFetchExpr)
      case errorSuppressExpr: HexrayErrorSuppressExpr     => astForErrorSuppressExpr(errorSuppressExpr)
      case instanceOfExpr: HexrayInstanceOfExpr           => astForInstanceOfExpr(instanceOfExpr)
      case propertyFetchExpr: HexrayPropertyFetchExpr     => astForPropertyFetchExpr(propertyFetchExpr)
      case includeExpr: HexrayIncludeExpr                 => astForIncludeExpr(includeExpr)
      case shellExecExpr: HexrayShellExecExpr             => astForShellExecExpr(shellExecExpr)
      case null =>
        logger.warn("expr was null")
        ???
      case other => throw new NotImplementedError(s"unexpected expression '$other' of type ${other.getClass}")
    }
  }

  private def intToLiteralAst(num: Int): Ast = {
    Ast(NewLiteral().code(num.toString).typeFullName(TypeConstants.Int))
  }

  private def astForBreakStmt(breakStmt: HexrayBreakStmt): Ast = {
    val code      = breakStmt.num.map(num => s"break($num)").getOrElse("break")
    val breakNode = controlStructureNode(breakStmt, ControlStructureTypes.BREAK, code)

    val argument = breakStmt.num.map(intToLiteralAst)

    controlStructureAst(breakNode, None, argument.toList)
  }

  private def astForContinueStmt(continueStmt: HexrayContinueStmt): Ast = {
    val code         = continueStmt.num.map(num => s"continue($num)").getOrElse("continue")
    val continueNode = controlStructureNode(continueStmt, ControlStructureTypes.CONTINUE, code)

    val argument = continueStmt.num.map(intToLiteralAst)

    controlStructureAst(continueNode, None, argument.toList)
  }

  private def astForBlockStmt(blockStmt: HexrayBlockStmt): Ast = {
    val lineNumber = line(blockStmt)
    stmtBodyBlockAst(blockStmt)
  }

  private def astForWhileStmt(whileStmt: HexrayWhileStmt): Ast = {
    val condition  = astForExpr(whileStmt.cond)
    val lineNumber = line(whileStmt)
    val code       = s"while (${condition.rootCodeOrEmpty})"
    val body       = stmtBodyBlockAst(whileStmt)

    whileAst(Option(condition), List(body), Option(code), lineNumber)
  }

  private def astForDoStmt(doStmt: HexrayDoStmt): Ast = {
    val condition  = astForExpr(doStmt.cond)
    val lineNumber = line(doStmt)
    val code       = s"do {...} while (${condition.rootCodeOrEmpty})"
    val body       = stmtBodyBlockAst(doStmt)

    doWhileAst(Option(condition), List(body), Option(code), lineNumber)
  }

  private def astForForStmt(stmt: HexrayForStmt): Ast = {
    val lineNumber = line(stmt)

    val initAsts      = astForExpr(stmt.inits) :: Nil
    val conditionAsts = astForExpr(stmt.conditions) :: Nil
    val loopExprAsts  = astForExpr(stmt.loopExprs) :: Nil

    val bodyAst = stmtBodyBlockAst(stmt)

    val initCode      = initAsts.map(_.rootCodeOrEmpty).mkString(",")
    val conditionCode = conditionAsts.map(_.rootCodeOrEmpty).mkString(",")
    val loopExprCode  = loopExprAsts.map(_.rootCodeOrEmpty).mkString(",")
    val forCode       = s"for ($initCode;$conditionCode;$loopExprCode)"

    val forNode = controlStructureNode(stmt, ControlStructureTypes.FOR, forCode)
    forAst(forNode, Nil, initAsts, conditionAsts, loopExprAsts, bodyAst)
  }

  private def astForIfStmt(ifStmt: HexrayIfStmt): Ast = {
    val condition = astForExpr(ifStmt.cond)
    val thenAst   = stmtBodyBlockAst(ifStmt)
    val elseAst   = ifStmt.elseStmt.map(els => stmtBodyBlockAst(els)).toList

    val ifNode = controlStructureNode(ifStmt, ControlStructureTypes.IF, ifStmt.code)

    controlStructureAst(ifNode, Option(condition), thenAst :: elseAst)
  }

  private def astForSwitchStmt(stmt: HexraySwitchStmt): Ast = {
    val conditionAst = astForExpr(stmt.condition)

    val switchNode =
      controlStructureNode(stmt, ControlStructureTypes.SWITCH, s"switch (${conditionAst.rootCodeOrEmpty})")

    val switchBodyBlock = blockNode(stmt)
    val entryAsts       = stmt.cases.flatMap(astsForSwitchCase)
    val switchBody      = Ast(switchBodyBlock).withChildren(entryAsts)

    controlStructureAst(switchNode, Option(conditionAst), switchBody :: Nil)
  }

  private def astForTryStmt(stmt: HexrayTryStmt): Ast = {
    val tryBody     = stmtBodyBlockAst(stmt)
    val catches     = stmt.catches.map(astForCatchStmt)
    val finallyBody = stmt.finallyStmt.map(fin => stmtBodyBlockAst(fin))

    val tryNode = controlStructureNode(stmt, ControlStructureTypes.TRY, "try { ... }")

    tryCatchAst(tryNode, tryBody, catches, finallyBody)
  }

  private def astForReturnStmt(stmt: HexrayReturnStmt): Ast = {
    val maybeExprAst = stmt.expr.map(astForExpr)
    val code         = stmt.code

    val node = returnNode(stmt, code)
    returnAst(node, maybeExprAst.toList)
  }

  private def astForClassLikeStmt(stmt: HexrayClassLikeStmt): Ast = {
    stmt.name match {
      case None       => astForAnonymousClass(stmt)
      case Some(name) => astForNamedClass(stmt, name)
    }
  }

  private def astForGotoStmt(stmt: HexrayGotoStmt): Ast = {
    val code = stmt.code

    val gotoNode = controlStructureNode(stmt, ControlStructureTypes.GOTO, code)

    val jumpLabel = NewJumpLabel()
      .name(stmt.label.name)
      .code(code)
      .lineNumber(line(stmt))
      .columnNumber(column(stmt))
    controlStructureAst(gotoNode, condition = None, children = Ast(jumpLabel) :: Nil)
  }

  private def astForLabelStmt(stmt: HexrayLabelStmt): Ast = {
    val label = stmt.label.name

    val jumpTarget = NewJumpTarget()
      .name(label)
      .code(label)
      .lineNumber(line(stmt))

    Ast(jumpTarget)
  }

  private def astForNamespaceStmt(stmt: HexrayNamespaceStmt): Ast = {
    val name     = stmt.name.map(_.name).getOrElse(NameConstants.Unknown)
    val fullName = s"$filename:$name"

    val namespaceBlock = NewNamespaceBlock()
      .name(name)
      .fullName(fullName)

    scope.pushNewScope(namespaceBlock)
    val bodyStmts = astsForClassLikeBody(stmt, stmt.stmts, createDefaultConstructor = false)
    scope.popScope()

    Ast(namespaceBlock).withChildren(bodyStmts)
  }

  private def astForDeclareStmt(stmt: HexrayDeclareStmt): Ast = {
    val declareAssignAsts = stmt.declares.map(astForDeclareItem)
    val declareCode       = s"${HexrayOperators.declareFunc}(${declareAssignAsts.map(_.rootCodeOrEmpty).mkString(",")})"
    val declareNode       = newOperatorCallNode(HexrayOperators.declareFunc, declareCode, line = line(stmt))
    val declareAst        = callAst(declareNode, declareAssignAsts)

    stmt.stmts match {
      case Some(stmtList) =>
        val stmtAsts = stmtList.flatMap(astsForStmt)
        Ast(blockNode(stmt))
          .withChild(declareAst)
          .withChildren(stmtAsts)

      case None => declareAst
    }
  }

  private def astForDeclareItem(item: HexrayDeclareItem): Ast = {
    val key   = identifierNode(item, item.key.name, item.key.name, "ANY")
    val value = astForExpr(item.value)
    val code  = s"${key.name}=${value.rootCodeOrEmpty}"

    val declareAssignment = newOperatorCallNode(Operators.assignment, code, line = line(item))
    callAst(declareAssignment, Ast(key) :: value :: Nil)
  }

  private def astForHaltCompilerStmt(stmt: HexrayHaltCompilerStmt): Ast = {
    val call = newOperatorCallNode(
      NameConstants.HaltCompiler,
      s"${NameConstants.HaltCompiler}()",
      Some(TypeConstants.Void),
      line(stmt),
      column(stmt)
    )

    Ast(call)
  }

  private def astForUnsetStmt(stmt: HexrayUnsetStmt): Ast = {
    val name = HexrayOperators.unset
    val args = stmt.vars.map(astForExpr)
    val code = s"$name(${args.map(_.rootCodeOrEmpty).mkString(", ")})"
    val callNode = newOperatorCallNode(name, code, typeFullName = Some(TypeConstants.Void), line = line(stmt))
      .methodFullName(HexrayOperators.unset)
    callAst(callNode, args)
  }

  private def astForGlobalStmt(stmt: HexrayGlobalStmt): Ast = {
    // This isn't an accurater representation of what `global` does, but with things like `global $$x` being possible,
    // it's very difficult to figure out correct scopes for global variables.

    val varsAsts = stmt.vars.map(astForExpr)
    val code     = s"${HexrayOperators.global} ${varsAsts.map(_.rootCodeOrEmpty).mkString(", ")}"

    val globalCallNode = newOperatorCallNode(HexrayOperators.global, code, Some(TypeConstants.Void), line(stmt))

    callAst(globalCallNode, varsAsts)
  }

  private def astForUseStmt(stmt: HexrayUseStmt): Ast = {
    // TODO Use useType + scope to get better name info
    val imports = stmt.uses.map(astForUseUse(_))
    wrapMultipleInBlock(imports, line(stmt))
  }

  private def astForGroupUseStmt(stmt: HexrayGroupUseStmt): Ast = {
    // TODO Use useType + scope to get better name info
    val groupPrefix = s"${stmt.prefix.name}\\"
    val imports     = stmt.uses.map(astForUseUse(_, groupPrefix))
    wrapMultipleInBlock(imports, line(stmt))
  }

  private def astForKeyValPair(key: HexrayExpr, value: HexrayExpr, lineNo: Option[Integer]): Ast = {
    val keyAst   = astForExpr(key)
    val valueAst = astForExpr(value)

    val code     = s"${keyAst.rootCodeOrEmpty} => ${valueAst.rootCodeOrEmpty}"
    val callNode = newOperatorCallNode(HexrayOperators.doubleArrow, code, line = lineNo)
    callAst(callNode, keyAst :: valueAst :: Nil)
  }

  private def astForForeachStmt(stmt: HexrayForeachStmt): Ast = {
    val iterIdentifier = getTmpIdentifier(stmt, maybeTypeFullName = None, prefix = "iter_")

    // keep this just used to construct the `code` field
    val assignItemTargetAst = stmt.keyVar match {
      case Some(key) => astForKeyValPair(key, stmt.valueVar, line(stmt))
      case None      => astForExpr(stmt.valueVar)
    }

    // Initializer asts
    // - Iterator assign
    val iterValue         = astForExpr(stmt.iterExpr)
    val iteratorAssignAst = simpleAssignAst(Ast(iterIdentifier), iterValue, line(stmt))

    // - Assigned item assign
    val itemInitAst = getItemAssignAstForForeach(stmt, iterIdentifier.copy)

    // Condition ast
    val isNullName = HexrayOperators.isNull
    val valueAst   = astForExpr(stmt.valueVar)
    val isNullCode = s"$isNullName(${valueAst.rootCodeOrEmpty})"
    val isNullCall = newOperatorCallNode(isNullName, isNullCode, Some(TypeConstants.Bool), line(stmt))
      .methodFullName(HexrayOperators.isNull)
    val notIsNull    = newOperatorCallNode(Operators.logicalNot, s"!$isNullCode", line = line(stmt))
    val isNullAst    = callAst(isNullCall, valueAst :: Nil)
    val conditionAst = callAst(notIsNull, isNullAst :: Nil)

    // Update asts
    val nextIterIdent = Ast(iterIdentifier.copy)
    val nextSignature = "void()"
    val nextCallCode  = s"${nextIterIdent.rootCodeOrEmpty}->next()"
    val nextCallNode = callNode(
      stmt,
      nextCallCode,
      "next",
      "Iterator.next",
      DispatchTypes.DYNAMIC_DISPATCH,
      Some(nextSignature),
      Some(TypeConstants.Any)
    )
    val nextCallAst = callAst(nextCallNode, base = Option(nextIterIdent))
    val itemUpdateAst = itemInitAst.root match {
      case Some(initRoot: AstNodeNew) => itemInitAst.subTreeCopy(initRoot)
      case _ =>
        logger.warn(s"Could not copy foreach init ast in $filename")
        Ast()
    }

    val bodyAst = stmtBodyBlockAst(stmt)

    val ampPrefix   = if (stmt.assignByRef) "&" else ""
    val foreachCode = s"foreach (${iterValue.rootCodeOrEmpty} as $ampPrefix${assignItemTargetAst.rootCodeOrEmpty})"
    val foreachNode = controlStructureNode(stmt, ControlStructureTypes.FOR, foreachCode)
    Ast(foreachNode)
      .withChild(wrapMultipleInBlock(iteratorAssignAst :: itemInitAst :: Nil, line(stmt)))
      .withChild(conditionAst)
      .withChild(wrapMultipleInBlock(nextCallAst :: itemUpdateAst :: Nil, line(stmt)))
      .withChild(bodyAst)
      .withConditionEdges(foreachNode, conditionAst.root.toList)
  }

  private def getItemAssignAstForForeach(stmt: HexrayForeachStmt, iteratorIdentifier: NewIdentifier): Ast = {
    // create assignment for value-part
    val valueAssign = {
      val iteratorIdentifierAst = Ast(iteratorIdentifier)
      val currentCallSignature  = s"$UnresolvedSignature(0)"
      val currentCallCode       = s"${iteratorIdentifierAst.rootCodeOrEmpty}->current()"
      // `current` function is used to get the current element of given array
      // see https://www.php.net/manual/en/function.current.php & https://www.php.net/manual/en/iterator.current.php
      val currentCallNode = callNode(
        stmt,
        currentCallCode,
        "current",
        "Iterator.current",
        DispatchTypes.DYNAMIC_DISPATCH,
        Some(currentCallSignature),
        Some(TypeConstants.Any)
      )
      val currentCallAst = callAst(currentCallNode, base = Option(iteratorIdentifierAst))

      val valueAst = if (stmt.assignByRef) {
        val addressOfCode = s"&${currentCallAst.rootCodeOrEmpty}"
        val addressOfCall = newOperatorCallNode(Operators.addressOf, addressOfCode, line = line(stmt))
        callAst(addressOfCall, currentCallAst :: Nil)
      } else {
        currentCallAst
      }
      simpleAssignAst(astForExpr(stmt.valueVar), valueAst, line(stmt))
    }

    // try to create assignment for key-part
    val keyAssignOption = stmt.keyVar.map(keyVar =>
      val iteratorIdentifierAst = Ast(iteratorIdentifier.copy)
      val keyCallSignature      = s"$UnresolvedSignature(0)"
      val keyCallCode           = s"${iteratorIdentifierAst.rootCodeOrEmpty}->key()"
      // `key` function is used to get the key of the current element
      // see https://www.php.net/manual/en/function.key.php & https://www.php.net/manual/en/iterator.key.php
      val keyCallNode = callNode(
        stmt,
        keyCallCode,
        "key",
        "Iterator.key",
        DispatchTypes.DYNAMIC_DISPATCH,
        Some(keyCallSignature),
        Some(TypeConstants.Any)
      )
      val keyCallAst = callAst(keyCallNode, base = Option(iteratorIdentifierAst))
      simpleAssignAst(astForExpr(keyVar), keyCallAst, line(stmt))
    )

    keyAssignOption match {
      case Some(keyAssign) =>
        Ast(blockNode(stmt))
          .withChild(keyAssign)
          .withChild(valueAssign)
      case None =>
        valueAssign
    }
  }

  private def simpleAssignAst(target: Ast, source: Ast, lineNo: Option[Integer]): Ast = {
    val code     = s"${target.rootCodeOrEmpty} = ${source.rootCodeOrEmpty}"
    val callNode = newOperatorCallNode(Operators.assignment, code, line = lineNo)
    callAst(callNode, target :: source :: Nil)
  }

  private def astforTraitUseStmt(stmt: HexrayTraitUseStmt): Ast = {
    // TODO Actually implement this
    Ast()
  }

  private def astForUseUse(stmt: HexrayUseUse, namePrefix: String = ""): Ast = {
    val originalName = s"$namePrefix${stmt.originalName.name}"
    val aliasCode    = stmt.alias.map(alias => s" as ${alias.name}").getOrElse("")
    val typeCode = stmt.useType match {
      case PhpUseType.Function => s"function "
      case PhpUseType.Constant => s"const "
      case _                   => ""
    }
    val code = s"use $typeCode$originalName$aliasCode"

    val importNode = NewImport()
      .importedEntity(originalName)
      .importedAs(stmt.alias.map(_.name))
      .isExplicit(true)
      .code(code)

    Ast(importNode)
  }

  private def astsForStaticStmt(stmt: HexrayStaticStmt): List[Ast] = {
    stmt.vars.flatMap { staticVarDecl =>
      staticVarDecl.variable match {
        case HexrayVariable(HeaxrayNameExpr(name, _), _) =>
          val maybeDefaultValueAst = staticVarDecl.defaultValue.map(astForExpr)

          val code         = s"static $$$name"
          val typeFullName = maybeDefaultValueAst.flatMap(_.rootType).getOrElse(TypeConstants.Any)

          val local = localNode(stmt, name, code, typeFullName)
          scope.addToScope(local.name, local)

          val assignmentAst = maybeDefaultValueAst.map { defaultValue =>
            val variableNode = identifierNode(stmt, name, s"$$$name", typeFullName)
            val variableAst  = Ast(variableNode).withRefEdge(variableNode, local)

            val assignCode = s"$code = ${defaultValue.rootCodeOrEmpty}"
            val assignNode = newOperatorCallNode(Operators.assignment, assignCode, line = line(stmt))

            callAst(assignNode, variableAst :: defaultValue :: Nil)
          }

          Ast(local) :: assignmentAst.toList

        case other =>
          logger.warn(s"Unexpected static variable type $other in $filename")
          Nil
      }
    }
  }

  private def astForAnonymousClass(stmt: HexrayClassLikeStmt): Ast = {
    // TODO
    Ast()
  }

  private def codeForClassStmt(stmt: HexrayClassLikeStmt, name: HeaxrayNameExpr): String = {
    // TODO Extend for anonymous classes
    val extendsString = stmt.extendsNames match {
      case Nil   => ""
      case names => s" extends ${names.map(_.name).mkString(", ")}"
    }
    val implementsString =
      if (stmt.implementedInterfaces.isEmpty)
        ""
      else
        s" implements ${stmt.implementedInterfaces.map(_.name).mkString(", ")}"

    s"${stmt.classLikeType} ${name.name}$extendsString$implementsString"
  }

  private def astForNamedClass(stmt: HexrayClassLikeStmt, name: HeaxrayNameExpr): Ast = {
    val inheritsFrom = (stmt.extendsNames ++ stmt.implementedInterfaces).map(_.name)
    val code         = codeForClassStmt(stmt, name)

    val fullName =
      if (name.name == NamespaceTraversal.globalNamespaceName)
        globalNamespace.fullName
      else {
        prependNamespacePrefix(name.name)
      }

    val typeDecl                 = typeDeclNode(stmt, name.name, fullName, filename, code, inherits = inheritsFrom)
    val createDefaultConstructor = stmt.hasConstructor

    scope.pushNewScope(typeDecl)
    val bodyStmts      = astsForClassLikeBody(stmt, stmt.stmts, createDefaultConstructor)
    val modifiers      = stmt.modifiers.map(newModifierNode).map(Ast(_))
    val annotationAsts = stmt.attributeGroups.flatMap(astForAttributeGroup)
    scope.popScope()

    Ast(typeDecl).withChildren(modifiers).withChildren(bodyStmts).withChildren(annotationAsts)
  }

  private def astForStaticAndConstInits: Option[Ast] = {
    scope.getConstAndStaticInits match {
      case Nil => None

      case inits =>
        val signature = s"${TypeConstants.Void}()"
        val fullName  = composeMethodFullName(StaticInitMethodName, isStatic = true)
        val ast = staticInitMethodAst(inits, fullName, Option(signature), TypeConstants.Void, fileName = Some(filename))
        Option(ast)
    }

  }

  private def astsForClassLikeBody(
    classLike: HexrayStmt,
    bodyStmts: List[HexrayStmt],
    createDefaultConstructor: Boolean
  ): List[Ast] = {
    val classConsts = bodyStmts.collect { case cs: HexrayConstStmt => cs }.flatMap(astsForConstStmt)
    val properties  = bodyStmts.collect { case cp: HexrayPropertyStmt => cp }.flatMap(astsForPropertyStmt)

    val explicitConstructorAst = bodyStmts.collectFirst {
      case m: HexrayMethodDecl if m.name == ConstructorMethodName => astForConstructor(m)
    }

    val constructorAst =
      explicitConstructorAst.orElse(Option.when(createDefaultConstructor)(defaultConstructorAst(classLike)))

    val otherBodyStmts = bodyStmts.flatMap {
      case _: HexrayConstStmt => Nil // Handled above

      case _: HexrayPropertyStmt => Nil // Handled above

      case method: HexrayMethodDecl if method.name == ConstructorMethodName => Nil // Handled above

      // Not all statements are supported in class bodies, but since this is re-used for namespaces
      // we allow that here.
      case stmt => astsForStmt(stmt)
    }

    val clinitAst           = astForStaticAndConstInits
    val anonymousMethodAsts = scope.getAndClearAnonymousMethods

    List(classConsts, properties, clinitAst, constructorAst, anonymousMethodAsts, otherBodyStmts).flatten
  }

  private def astForConstructor(constructorDecl: HexrayMethodDecl): Ast = {
    val fieldInits = scope.getFieldInits
    astForMethodDecl(constructorDecl, fieldInits, isConstructor = true)
  }

  private def prependNamespacePrefix(name: String): String = {
    scope.getEnclosingNamespaceNames.filterNot(_ == NamespaceTraversal.globalNamespaceName) match {
      case Nil   => name
      case names => names.appended(name).mkString(NamespaceDelimiter)
    }
  }

  private def getTypeDeclPrefix: Option[String] = {
    scope.getEnclosingTypeDeclTypeName
      .filterNot(_ == NamespaceTraversal.globalNamespaceName)
  }

  private def defaultConstructorAst(originNode: HexrayNode): Ast = {
    val fullName = composeMethodFullName(ConstructorMethodName, isStatic = false)

    val signature = s"$UnresolvedSignature(0)"

    val modifiers = List(ModifierTypes.VIRTUAL, ModifierTypes.PUBLIC, ModifierTypes.CONSTRUCTOR).map(newModifierNode)

    val thisParam = thisParamAstForMethod(originNode)

    val method = methodNode(originNode, ConstructorMethodName, fullName, fullName, Some(signature), filename)

    val methodBody = blockAst(blockNode(originNode), scope.getFieldInits)

    val methodReturn = newMethodReturnNode(TypeConstants.Any, line = None, column = None)

    methodAstWithAnnotations(method, thisParam :: Nil, methodBody, methodReturn, modifiers)
  }

  private def astForMemberAssignment(memberNode: NewMember, valueExpr: HexrayExpr, isField: Boolean): Ast = {
    val targetAst = if (isField) {
      val code            = s"$$this->${memberNode.name}"
      val fieldAccessNode = newOperatorCallNode(Operators.fieldAccess, code, line = memberNode.lineNumber)
      val identifier      = thisIdentifier(memberNode.lineNumber)
      val thisParam       = scope.lookupVariable(NameConstants.This)
      val fieldIdentifier = newFieldIdentifierNode(memberNode.name, memberNode.lineNumber)
      callAst(fieldAccessNode, List(identifier, fieldIdentifier).map(Ast(_))).withRefEdges(identifier, thisParam.toList)
    } else {
      val identifierCode = memberNode.code.replaceAll("const ", "").replaceAll("case ", "")
      val typeFullName   = Option(memberNode.typeFullName)
      val identifier = newIdentifierNode(memberNode.name, typeFullName.getOrElse("ANY"))
        .code(identifierCode)
      Ast(identifier).withRefEdge(identifier, memberNode)
    }
    val value = astForExpr(valueExpr)

    val assignmentCode = s"${targetAst.rootCodeOrEmpty} = ${value.rootCodeOrEmpty}"
    val callNode       = newOperatorCallNode(Operators.assignment, assignmentCode, line = memberNode.lineNumber)

    callAst(callNode, List(targetAst, value))
  }

  private def astsForConstStmt(stmt: HexrayConstStmt): List[Ast] = {
    stmt.consts.map { constDecl =>
      val finalModifier = Ast(newModifierNode(ModifierTypes.FINAL))
      // `final const` is not allowed, so this is a safe way to represent constants in the CPG
      val modifierAsts = finalModifier :: stmt.modifiers.map(newModifierNode).map(Ast(_))

      val name      = constDecl.name.name
      val code      = s"const $name"
      val someValue = Option(constDecl.value)
      astForConstOrFieldValue(stmt, name, code, someValue, scope.addConstOrStaticInitToScope, isField = false)
        .withChildren(modifierAsts)
    }
  }

  private def astForEnumCase(stmt: HexrayEnumCaseStmt): Ast = {
    val finalModifier = Ast(newModifierNode(ModifierTypes.FINAL))

    val name = stmt.name.name
    val code = s"case $name"

    astForConstOrFieldValue(stmt, name, code, stmt.expr, scope.addConstOrStaticInitToScope, isField = false)
      .withChild(finalModifier)
  }

  private def astsForPropertyStmt(stmt: HexrayPropertyStmt): List[Ast] = {
    stmt.variables.map { varDecl =>
      val modifierAsts = stmt.modifiers.map(newModifierNode).map(Ast(_))

      val name = varDecl.name.name
      astForConstOrFieldValue(stmt, name, s"$$$name", varDecl.defaultValue, scope.addFieldInitToScope, isField = true)
        .withChildren(modifierAsts)
    }
  }

  private def astForConstOrFieldValue(
    originNode: HexrayNode,
    name: String,
    code: String,
    value: Option[HexrayExpr],
    addToScope: Ast => Unit,
    isField: Boolean
  ): Ast = {
    val member = memberNode(originNode, name, code, TypeConstants.Any)

    value match {
      case Some(v) =>
        val assignAst = astForMemberAssignment(member, v, isField)
        addToScope(assignAst)
      case None => // Nothing to do here
    }

    Ast(member)
  }

  private def astForCatchStmt(stmt: HexrayCatchStmt): Ast = {
    // TODO Add variable at some point. Current implementation is consistent with C++.
    stmtBodyBlockAst(stmt)
  }

  private def astsForSwitchCase(caseStmt: HexrayCaseStmt): List[Ast] = {
    val maybeConditionAst = caseStmt.condition.map(astForExpr)

    val jumpTarget = maybeConditionAst.map(elem =>
      elem match {
        case _ =>
          NewJumpTarget().name("case").lineNumber(line(caseStmt))
      }
    )
    val stmtAsts = caseStmt.stmts.flatMap(astsForStmt)
    Ast(jumpTarget) :: maybeConditionAst.toList ++ stmtAsts
  }

  private def codeForMethodCall(call: HexrayCallExpr, targetAst: Ast, name: String): String = {
    val callOperator = if (call.isNullSafe) "?->" else "->"
    s"${targetAst.rootCodeOrEmpty}$callOperator$name"
  }

  private def astForCall(call: HexrayCallExpr): Ast = {
    val arguments = call.args.map(astForCallArg)

    val nameAst = Option.unless(call.methodName.isInstanceOf[HeaxrayNameExpr])(astForExpr(call.methodName))
    val name =
      nameAst
        .map(_.rootCodeOrEmpty)
        .getOrElse(call.methodName match {
          case nameExpr: HeaxrayNameExpr => nameExpr.name
          case other =>
            logger.error(s"Found unexpected call target type: Crash for now to handle properly later: $other")
            ???
        })

    val code = call.code

    val dispatchType = DispatchTypes.STATIC_DISPATCH
    val fullName     = name

    // Use method signature for methods that can be linked to avoid varargs issue.
    val signature = s"$UnresolvedSignature(${call.args.size})"
    val callRoot  = callNode(call, code, name, fullName, dispatchType, Some(signature), Some(TypeConstants.Any))

    callAst(callRoot, arguments)
  }

  private def astForCallArg(arg: HexrayArgument): Ast = {
    arg match {
      case HexrayArg(expr, _, _) =>
        astForExpr(expr)

      case _: HexrayVariadicPlaceholder =>
        val identifier = identifierNode(arg, "...", "...", TypeConstants.VariadicPlaceholder)
        Ast(identifier)
    }
  }

  private def astForVariableExpr(variable: HexrayVariable): Ast = {
    // TODO Need to figure out variable variables. Maybe represent as some kind of call?
    val valueAst = astForExpr(variable.value)
    valueAst
  }

  private def astForNameExpr(expr: HeaxrayNameExpr): Ast = {
    val identifier    = identifierNode(expr, expr.name, expr.name, TypeConstants.Any)
    val declaringNode = scope.lookupVariable(identifier.name)
    Ast(identifier).withRefEdges(identifier, declaringNode.toList)
  }

  private def astForAssignment(assignment: HexrayAssignment): Ast = {
    assignment.target match {
      case _ =>
        val operatorName = assignment.assignOp

        val targetAst = astForExpr(assignment.target)
        val sourceAst = astForExpr(assignment.source)

        // TODO Handle ref assigns properly (if needed).
        val refSymbol = if (assignment.isRefAssign) "&" else ""
        val symbol    = operatorSymbols.getOrElse(assignment.assignOp, assignment.assignOp)
        val code      = assignment.code
        val callNode  = newOperatorCallNode(operatorName, code, line = line(assignment))
        callAst(callNode, List(targetAst, sourceAst))
    }
  }

  private def astForEncapsed(encapsed: HexrayEncapsed): Ast = {
    val args = encapsed.parts.map(astForExpr)
    val code = args.map(_.rootCodeOrEmpty).mkString(" . ")

    args match {
      case singleArg :: Nil => singleArg
      case _ =>
        val callNode = newOperatorCallNode(HexrayOperators.encaps, code, Some(TypeConstants.String), line(encapsed))
        callAst(callNode, args)
    }
  }

  private def astForScalar(scalar: HexrayScalar): Ast = {
    scalar match {
      case encapsed: HexrayEncapsed         => astForEncapsed(encapsed)
      case simpleScalar: HexraySimpleScalar => Ast(literalNode(scalar, simpleScalar.value, simpleScalar.typeFullName))
      case null =>
        logger.warn("scalar was null")
        ???
    }
  }

  private def astForBinOp(binOp: HexrayBinaryOp): Ast = {
    val leftAst  = astForExpr(binOp.left)
    val rightAst = astForExpr(binOp.right)

    val symbol = operatorSymbols.getOrElse(binOp.operator, binOp.operator)
    val code   = binOp.code

    val callNode = newOperatorCallNode(binOp.operator, code, line = line(binOp))
    callAst(callNode, List(leftAst, rightAst))
  }

  private def isPostfixOperator(operator: String): Boolean = {
    Set(Operators.postDecrement, Operators.postIncrement).contains(operator)
  }

  private def astForUnaryOp(unaryOp: HexrayUnaryOp): Ast = {
    val exprAst = astForExpr(unaryOp.expr)

    val symbol   = operatorSymbols.getOrElse(unaryOp.operator, unaryOp.operator)
    val code     = unaryOp.code
    val callNode = newOperatorCallNode(unaryOp.operator, code, line = line(unaryOp))
    callAst(callNode, exprAst :: Nil)
  }

  private def astForCastExpr(castExpr: HexrayCast): Ast = {
    val typeFullName = castExpr.typ
    val typ          = typeRefNode(castExpr, typeFullName, typeFullName)
    val expr         = astForExpr(castExpr.expr)

    val cpgCastExpression =
      callNode(castExpr, castExpr.code, Operators.cast, Operators.cast, DispatchTypes.STATIC_DISPATCH)

    callAst(cpgCastExpression, List(Ast(typ), expr))
  }

  private def astForMemberPtrExpr(expr: HexrayMemberPtrExpr): Ast = {
    var op        = Operators.indirectFieldAccess
    val callNode_ = callNode(expr, expr.code, op, op, DispatchTypes.STATIC_DISPATCH)
    val left      = astForExpr(expr.variable)
    val member    = fieldIdentifierNode(expr.member, expr.member.name, expr.member.name)
    callAst(callNode_, List(left, Ast(member)))
  }

  private def astForIsSetExpr(isSetExpr: HexrayIsset): Ast = {
    val name = HexrayOperators.issetFunc
    val args = isSetExpr.vars.map(astForExpr)
    val code = s"$name(${args.map(_.rootCodeOrEmpty).mkString(",")})"

    val callNode =
      newOperatorCallNode(name, code, typeFullName = Some(TypeConstants.Bool), line = line(isSetExpr))
        .methodFullName(HexrayOperators.issetFunc)

    callAst(callNode, args)
  }

  private def astForEmpty(expr: HexrayEmptyExpr): Ast = {
    val name = HexrayOperators.emptyFunc
    val code = "empty"
    val callNode = newOperatorCallNode(name, code, Some(TypeConstants.Void), line(expr))
      .methodFullName(HexrayOperators.emptyFunc)
    callAst(callNode)
  }

  private def astForCommaExpr(expr: HexrayCommaExpr): Ast = {
    val x         = astForExpr(expr.x)
    val y         = astForExpr(expr.y)
    val bodyBlock = blockNode(expr)
    Ast(bodyBlock).withChildren(List(x, y))

  }

  private def getTmpIdentifier(
    originNode: HexrayNode,
    maybeTypeFullName: Option[String],
    prefix: String = ""
  ): NewIdentifier = {
    val name         = s"$prefix${getNewTmpName()}"
    val typeFullName = maybeTypeFullName.getOrElse(TypeConstants.Any)
    identifierNode(originNode, name, s"$$$name", typeFullName)
  }

  private def astForArrayExpr(expr: HexrayArrayExpr): Ast = {
    val idxTracker = new ArrayIndexTracker

    val tmpName = getNewTmpName()

    def newTmpIdentifier: Ast = Ast(identifierNode(expr, tmpName, s"$$$tmpName", TypeConstants.Array))

    val tmpIdentifierAssignNode = {
      // use array() function to create an empty array. see https://www.php.net/manual/zh/function.array.php
      val initArrayNode = callNode(
        expr,
        "array()",
        "array",
        "array",
        DispatchTypes.STATIC_DISPATCH,
        Some("array()"),
        Some(TypeConstants.Array)
      )
      val initArrayCallAst = callAst(initArrayNode)

      val assignCode = s"$$$tmpName = ${initArrayCallAst.rootCodeOrEmpty}"
      val assignNode = newOperatorCallNode(Operators.assignment, assignCode, line = line(expr))
      callAst(assignNode, newTmpIdentifier :: initArrayCallAst :: Nil)
    }

    val itemAssignments = expr.items.flatMap {
      case Some(item) => Option(assignForArrayItem(item, tmpName, idxTracker))
      case None =>
        idxTracker.next // Skip an index
        None
    }
    val arrayBlock = blockNode(expr)

    Ast(arrayBlock)
      .withChild(tmpIdentifierAssignNode)
      .withChildren(itemAssignments)
      .withChild(newTmpIdentifier)
  }

  private def astForListExpr(expr: HexrayListExpr): Ast = {
    /* TODO: Handling list in a way that will actually work with dataflow tracking is somewhat more complicated than
     *  this and will likely need a fairly ugly lowering.
     *
     * In short, the case:
     *   list($a, $b) = $arr;
     * can be lowered to:
     *   $a = $arr[0];
     *   $b = $arr[1];
     *
     * the case:
     *   list("id" => $a, "name" => $b) = $arr;
     * can be lowered to:
     *   $a = $arr["id"];
     *   $b = $arr["name"];
     *
     * and the case:
     *   foreach ($arr as list($a, $b)) { ... }
     * can be lowered as above for each $arr[i];
     *
     * The below is just a placeholder to prevent crashes while figuring out the cleanest way to
     * implement the above lowering or to think of a better way to do it.
     */

    val name     = HexrayOperators.listFunc
    val args     = expr.items.flatten.map { item => astForExpr(item.value) }
    val listCode = s"$name(${args.map(_.rootCodeOrEmpty).mkString(",")})"
    val listNode = newOperatorCallNode(name, listCode, line = line(expr))
      .methodFullName(HexrayOperators.listFunc)

    callAst(listNode, args)
  }

  private def astForMatchExpr(expr: HexrayMatchExpr): Ast = {
    val conditionAst = astForExpr(expr.condition)

    val matchNode = controlStructureNode(expr, ControlStructureTypes.MATCH, s"match (${conditionAst.rootCodeOrEmpty})")

    val matchBodyBlock = blockNode(expr)
    val armsAsts       = expr.matchArms.flatMap(astsForMatchArm)
    val matchBody      = Ast(matchBodyBlock).withChildren(armsAsts)

    controlStructureAst(matchNode, Option(conditionAst), matchBody :: Nil)
  }

  private def astsForMatchArm(matchArm: HexrayMatchArm): List[Ast] = {
    val targetAsts = matchArm.conditions.flatMap { condition =>
      val conditionAst = astForExpr(condition)
      // In PHP cases aren't labeled with `case`, but this is used by the CFG creator to differentiate between
      // case/default labels and other labels.
      val code          = s"case ${conditionAst.rootCode.getOrElse(NameConstants.Unknown)}"
      val jumpTargetAst = Ast(NewJumpTarget().name(code).code(code).lineNumber(line(condition)))
      jumpTargetAst :: conditionAst :: Nil
    }
    val defaultLabel = Option.when(matchArm.isDefault)(
      Ast(NewJumpTarget().name(NameConstants.Default).code(NameConstants.Default).lineNumber(line(matchArm)))
    )

    val bodyAst = astForExpr(matchArm.body)

    targetAsts ++ defaultLabel :+ bodyAst
  }

  private def astForYieldExpr(expr: HexrayYieldExpr): Ast = {
    val maybeKey = expr.key.map(astForExpr)
    val maybeVal = expr.value.map(astForExpr)

    val code = (maybeKey, maybeVal) match {
      case (Some(key), Some(value)) =>
        s"yield ${key.rootCodeOrEmpty} => ${value.rootCodeOrEmpty}"

      case _ =>
        s"yield ${maybeKey.map(_.rootCodeOrEmpty).getOrElse("")}${maybeVal.map(_.rootCodeOrEmpty).getOrElse("")}".trim
    }

    val yieldNode = controlStructureNode(expr, ControlStructureTypes.YIELD, code)

    Ast(yieldNode)
      .withChildren(maybeKey.toList)
      .withChildren(maybeVal.toList)
  }

  private def astForSimpleNewExpr(expr: HexrayNewExpr, classNameExpr: HexrayExpr): Ast = {
    val (maybeNameAst, className) = classNameExpr match {
      case nameExpr: HeaxrayNameExpr =>
        (None, nameExpr.name)

      case expr: HexrayExpr =>
        val ast = astForExpr(expr)
        // The name doesn't make sense in this case, but the AST will be more useful
        val name = ast.rootCode.getOrElse(NameConstants.Unknown)
        (Option(ast), name)
    }

    val tmpIdentifier = getTmpIdentifier(expr, Option(className))

    // Alloc assign
    val allocCode       = s"$className.<alloc>()"
    val allocNode       = newOperatorCallNode(Operators.alloc, allocCode, Option(className), line(expr))
    val allocAst        = callAst(allocNode, base = maybeNameAst)
    val allocAssignCode = s"${tmpIdentifier.code} = ${allocAst.rootCodeOrEmpty}"
    val allocAssignNode = newOperatorCallNode(Operators.assignment, allocAssignCode, Option(className), line(expr))
    val allocAssignAst  = callAst(allocAssignNode, Ast(tmpIdentifier) :: allocAst :: Nil)

    // Init node
    val initArgs      = expr.args.map(astForCallArg)
    val initSignature = s"$UnresolvedSignature(${initArgs.size})"
    val initFullName  = s"$className$InstanceMethodDelimiter$ConstructorMethodName"
    val initCode      = s"$initFullName(${initArgs.map(_.rootCodeOrEmpty).mkString(",")})"
    val initCallNode = callNode(
      expr,
      initCode,
      ConstructorMethodName,
      initFullName,
      DispatchTypes.DYNAMIC_DISPATCH,
      Some(initSignature),
      Some(TypeConstants.Any)
    )
    val initReceiver = Ast(tmpIdentifier.copy)
    val initCallAst  = callAst(initCallNode, initArgs, base = Option(initReceiver))

    // Return identifier
    val returnIdentifierAst = Ast(tmpIdentifier.copy)

    Ast(blockNode(expr, "", TypeConstants.Any))
      .withChild(allocAssignAst)
      .withChild(initCallAst)
      .withChild(returnIdentifierAst)
  }

  private def dimensionFromSimpleScalar(scalar: HexraySimpleScalar, idxTracker: ArrayIndexTracker): HexrayExpr = {
    val maybeIntValue = scalar match {
      case string: HexrayString =>
        string.value
          .drop(1)
          .dropRight(1)
          .toIntOption

      case number => number.value.toIntOption
    }

    maybeIntValue match {
      case Some(intValue) =>
        idxTracker.updateValue(intValue)
        HexrayInt(intValue.toString, scalar.attributes)

      case None =>
        scalar
    }
  }

  private def assignForArrayItem(item: HexrayArrayItem, name: String, idxTracker: ArrayIndexTracker): Ast = {
    // It's perhaps a bit clumsy to reconstruct PhpExpr nodes here, but reuse astForArrayDimExpr for consistency
    val variable = HexrayVariable(HeaxrayNameExpr(name, item.attributes), item.attributes)

    val dimension = item.key match {
      case Some(key: HexraySimpleScalar) => dimensionFromSimpleScalar(key, idxTracker)
      case Some(key)                     => key
      case None                          => HexrayInt(idxTracker.next, item.attributes)
    }

    val dimFetchNode = HexrayArrayIndexExpr("", variable, dimension, item.attributes)
    val dimFetchAst  = astForArrayIndexExpr(dimFetchNode)

    val valueAst = astForArrayItemValue(item)

    val assignCode = s"${dimFetchAst.rootCodeOrEmpty} = ${valueAst.rootCodeOrEmpty}"

    val assignNode = newOperatorCallNode(Operators.assignment, assignCode, line = line(item))

    callAst(assignNode, dimFetchAst :: valueAst :: Nil)
  }

  private def astForArrayItemValue(item: HexrayArrayItem): Ast = {
    val exprAst   = astForExpr(item.value)
    val valueCode = exprAst.rootCodeOrEmpty

    if (item.byRef) {
      val parentCall = newOperatorCallNode(Operators.addressOf, s"&$valueCode", line = line(item))
      callAst(parentCall, exprAst :: Nil)
    } else if (item.unpack) {
      val parentCall = newOperatorCallNode(HexrayOperators.unpack, s"...$valueCode", line = line(item))
      callAst(parentCall, exprAst :: Nil)
    } else {
      exprAst
    }
  }

  private def astForArrayIndexExpr(expr: HexrayArrayIndexExpr): Ast = {
    val variableAst  = astForExpr(expr.variable)
    val variableCode = variableAst.rootCodeOrEmpty

    val indexAst   = astForExpr(expr.index)
    val code       = expr.code
    val accessNode = newOperatorCallNode(Operators.indexAccess, code, line = line(expr))
    callAst(accessNode, variableAst :: indexAst :: Nil)
  }

  private def astForErrorSuppressExpr(expr: HexrayErrorSuppressExpr): Ast = {
    val childAst = astForExpr(expr.expr)

    val code         = s"@${childAst.rootCodeOrEmpty}"
    val suppressNode = newOperatorCallNode(HexrayOperators.errorSuppress, code, line = line(expr))
    childAst.rootType.foreach(typ => suppressNode.typeFullName(typ))

    callAst(suppressNode, childAst :: Nil)
  }

  private def astForInstanceOfExpr(expr: HexrayInstanceOfExpr): Ast = {
    val exprAst  = astForExpr(expr.expr)
    val classAst = astForExpr(expr.className)

    val code           = s"${exprAst.rootCodeOrEmpty} instanceof ${classAst.rootCodeOrEmpty}"
    val instanceOfNode = newOperatorCallNode(Operators.instanceOf, code, Some(TypeConstants.Bool), line(expr))

    callAst(instanceOfNode, exprAst :: classAst :: Nil)
  }

  private def astForPropertyFetchExpr(expr: HexrayPropertyFetchExpr): Ast = {
    val objExprAst = astForExpr(expr.expr)

    val fieldAst = expr.name match {
      case name: HeaxrayNameExpr => Ast(newFieldIdentifierNode(name.name, line(expr)))
      case other                 => astForExpr(other)
    }

    val accessSymbol =
      if (expr.isStatic)
        "::"
      else if (expr.isNullsafe)
        "?->"
      else
        "->"

    val code            = s"${objExprAst.rootCodeOrEmpty}$accessSymbol${fieldAst.rootCodeOrEmpty}"
    val fieldAccessNode = newOperatorCallNode(Operators.fieldAccess, code, line = line(expr))

    callAst(fieldAccessNode, objExprAst :: fieldAst :: Nil)
  }

  private def astForIncludeExpr(expr: HexrayIncludeExpr): Ast = {
    val exprAst  = astForExpr(expr.expr)
    val code     = s"${expr.includeType} ${exprAst.rootCodeOrEmpty}"
    val callNode = newOperatorCallNode(expr.includeType, code, line = line(expr))

    callAst(callNode, exprAst :: Nil)
  }

  private def astForShellExecExpr(expr: HexrayShellExecExpr): Ast = {
    val args = astForEncapsed(expr.parts)
    val code = "`" + args.rootCodeOrEmpty + "`"

    val callNode = newOperatorCallNode(HexrayOperators.shellExec, code, line = line(expr))

    callAst(callNode, args :: Nil)
  }

  private def astForMagicClassConstant(expr: HexrayClassConstFetchExpr): Ast = {
    val typeFullName = expr.className match {
      case nameExpr: HeaxrayNameExpr =>
        scope
          .lookupVariable(nameExpr.name)
          .flatMap(_.properties.get(PropertyNames.TYPE_FULL_NAME).map(_.toString))
          .getOrElse(nameExpr.name)

      case expr =>
        logger.warn(s"Unexpected expression as class name in <class>::class expression: $filename")
        NameConstants.Unknown
    }

    Ast(typeRefNode(expr, s"$typeFullName::class", typeFullName))
  }

  private def astForClassConstFetchExpr(expr: HexrayClassConstFetchExpr): Ast = {
    expr.constantName match {
      // Foo::class should be a TypeRef and not a field access
      case Some(constNameExpr) if constNameExpr.name == NameConstants.Class =>
        astForMagicClassConstant(expr)

      case _ =>
        val targetAst           = astForExpr(expr.className)
        val fieldIdentifierName = expr.constantName.map(_.name).getOrElse(NameConstants.Unknown)
        val fieldIdentifier     = newFieldIdentifierNode(fieldIdentifierName, line(expr))
        val fieldAccessCode     = s"${targetAst.rootCodeOrEmpty}::${fieldIdentifier.code}"
        val fieldAccessCall     = newOperatorCallNode(Operators.fieldAccess, fieldAccessCode, line = line(expr))
        callAst(fieldAccessCall, List(targetAst, Ast(fieldIdentifier)))
    }
  }

  private def astForConstFetchExpr(expr: HexrayConstFetchExpr): Ast = {
    val constName = expr.name.name

    if (NameConstants.isBoolean(constName)) {
      Ast(literalNode(expr, constName, TypeConstants.Bool))
    } else if (NameConstants.isNull(constName)) {
      Ast(literalNode(expr, constName, TypeConstants.NullType))
    } else {
      val namespaceName   = NamespaceTraversal.globalNamespaceName
      val identifier      = identifierNode(expr, namespaceName, namespaceName, "ANY")
      val fieldIdentifier = newFieldIdentifierNode(constName, line = line(expr))

      val fieldAccessNode = newOperatorCallNode(Operators.fieldAccess, code = constName, line = line(expr))
      val args            = List(identifier, fieldIdentifier).map(Ast(_))

      callAst(fieldAccessNode, args)
    }
  }

  protected def line(hexrayNode: HexrayNode): Option[Integer] = Option(hexrayNode.attributes.ea)

  protected def column(hexrayNode: HexrayNode): Option[Integer] = Option(hexrayNode.attributes.treeidx)

  protected def lineEnd(phpNode: HexrayNode): Option[Integer] = None

  protected def columnEnd(phpNode: HexrayNode): Option[Integer] = None

  protected def code(hexrayNode: HexrayNode): String = "" // Sadly, the Php AST does not carry any code fields

  override protected def offset(hexrayNode: HexrayNode): Option[(Int, Int)] = {
    Option((hexrayNode.attributes.ea, hexrayNode.attributes.ea))
  }
}

object AstCreator {
  object TypeConstants {
    val String: String              = "string"
    val Int: String                 = "int"
    val Float: String               = "float"
    val Bool: String                = "bool"
    val Void: String                = "void"
    val Any: String                 = "ANY"
    val Array: String               = "array"
    val NullType: String            = "null"
    val VariadicPlaceholder: String = "PhpVariadicPlaceholder"
  }

  object NameConstants {
    val Default: String      = "default"
    val HaltCompiler: String = "__halt_compiler"
    val This: String         = "this"
    val Unknown: String      = "UNKNOWN"
    val Closure: String      = "__closure"
    val Class: String        = "class"
    val True: String         = "true"
    val False: String        = "false"
    val NullName: String     = "null"

    def isBoolean(name: String): Boolean = {
      List(True, False).contains(name)
    }

    def isNull(name: String): Boolean = {
      name.toLowerCase == NullName
    }
  }

  val operatorSymbols: Map[String, String] = Map(
    Operators.and                            -> "&",
    Operators.or                             -> "|",
    Operators.xor                            -> "^",
    Operators.logicalAnd                     -> "&&",
    Operators.logicalOr                      -> "||",
    HexrayOperators.coalesceOp               -> "??",
    HexrayOperators.concatOp                 -> ".",
    Operators.division                       -> "/",
    Operators.equals                         -> "==",
    Operators.greaterEqualsThan              -> ">=",
    Operators.greaterThan                    -> ">",
    HexrayOperators.identicalOp              -> "===",
    HexrayOperators.logicalXorOp             -> "xor",
    Operators.minus                          -> "-",
    Operators.modulo                         -> "%",
    Operators.multiplication                 -> "*",
    Operators.notEquals                      -> "!=",
    HexrayOperators.notIdenticalOp           -> "!==",
    Operators.plus                           -> "+",
    Operators.exponentiation                 -> "**",
    Operators.shiftLeft                      -> "<<",
    Operators.arithmeticShiftRight           -> ">>",
    Operators.lessEqualsThan                 -> "<=",
    Operators.lessThan                       -> "<",
    HexrayOperators.spaceshipOp              -> "<=>",
    Operators.not                            -> "~",
    Operators.logicalNot                     -> "!",
    Operators.postDecrement                  -> "--",
    Operators.postIncrement                  -> "++",
    Operators.preDecrement                   -> "--",
    Operators.preIncrement                   -> "++",
    Operators.minus                          -> "-",
    Operators.plus                           -> "+",
    Operators.assignment                     -> "=",
    Operators.assignmentAnd                  -> "&=",
    Operators.assignmentOr                   -> "|=",
    Operators.assignmentXor                  -> "^=",
    HexrayOperators.assignmentCoalesceOp     -> "??=",
    HexrayOperators.assignmentConcatOp       -> ".=",
    Operators.assignmentDivision             -> "/=",
    Operators.assignmentMinus                -> "-=",
    Operators.assignmentModulo               -> "%=",
    Operators.assignmentMultiplication       -> "*=",
    Operators.assignmentPlus                 -> "+=",
    Operators.assignmentExponentiation       -> "**=",
    Operators.assignmentShiftLeft            -> "<<=",
    Operators.assignmentArithmeticShiftRight -> ">>="
  )

}
