package io.joern.ida2cpg

import io.joern.ida2cpg.parser.HexraysParser
import io.joern.ida2cpg.passes.*
import io.joern.x2cpg.X2Cpg.withNewEmptyCpg
import io.joern.x2cpg.{SourceFiles, X2CpgFrontend}
import io.joern.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass, XTypeRecoveryConfig}
import io.joern.x2cpg.utils.ExternalCommand
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPassBase
import io.shiftleft.codepropertygraph.generated.Languages
import org.slf4j.LoggerFactory

import scala.collection.mutable
import scala.util.{Failure, Success, Try}
import scala.util.matching.Regex


class Ida2Cpg extends X2CpgFrontend[Config] {

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def createCpg(config: Config): Try[Cpg] = {
    val parser = HexraysParser.getParser(config)

    withNewEmptyCpg(config.outputPath, config: Config) { (cpg, config) =>
      new MetaDataPass(cpg, Languages.C, config.inputPath).createAndApply()
      new AstCreationPass(config, cpg, parser.get)(config.schemaValidation).createAndApply()
    }
  }

  private def buildFiles(config: Config): List[String] = {
    SourceFiles
      .determine(
        config.inputPath,
        Set(".json"),
        Option(config.defaultIgnoredFilesRegex),
        Option(config.ignoredFilesRegex),
        Option(config.ignoredFiles)
      )
      .filter(_.endsWith("composer.json"))
  }
}
