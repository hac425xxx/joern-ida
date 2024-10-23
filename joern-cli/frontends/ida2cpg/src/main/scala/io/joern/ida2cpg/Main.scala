package io.joern.ida2cpg

import io.joern.ida2cpg.Frontend.cmdLineParser
import io.joern.x2cpg.{X2CpgConfig, X2CpgMain}
import io.joern.x2cpg.passes.frontend.{TypeRecoveryParserConfig, XTypeRecovery}
import io.joern.ida2cpg.Frontend.defaultConfig
import scopt.OParser

/** Command line configuration parameters
  */
final case class Config(phpIni: Option[String] = None, phpParserBin: Option[String] = None)
    extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config] {
  def withPhpIni(phpIni: String): Config = {
    copy(phpIni = Some(phpIni)).withInheritedFields(this)
  }

  def withPhpParserBin(phpParserBin: String): Config = {
    copy(phpParserBin = Some(phpParserBin)).withInheritedFields(this)
  }
}
object Frontend {

  implicit val defaultConfig: Config = Config()

  val cmdLineParser: OParser[Unit, Config] = {
    val builder = OParser.builder[Config]
    import builder.*
    OParser.sequence(programName("ida2cpg"), XTypeRecovery.parserOptions)
  }
}


object Main extends X2CpgMain(cmdLineParser, new Ida2Cpg()) {
  def run(config: Config, ida2Cpg: Ida2Cpg): Unit = {
    ida2Cpg.run(config)
  }
}