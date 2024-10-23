package io.joern.ida2cpg.parser

import better.files.File
import io.joern.ida2cpg.Config
import io.joern.ida2cpg.parser.Domain.HexrayFile
import io.joern.x2cpg.utils.ExternalCommand
import org.slf4j.LoggerFactory

import java.nio.file.Paths
import scala.io.Source
import scala.util.{Failure, Success, Try}

class HexraysParser private(disableFileContent: Boolean) {

  private val logger = LoggerFactory.getLogger(this.getClass)


  def parseFile(inputPath: String): Option[(HexrayFile, Option[String])] = {
    val inputFile = File(inputPath)
    var source = Source.fromFile(inputPath)
    var output = source.mkString

    val content = Option.unless(disableFileContent)(inputFile.contentAsString)
    processParserOutput(output, inputPath).map((_, content))

  }

  private def processParserOutput(output: String, filename: String): Option[HexrayFile] = {
    val maybeJson = toJson(output, filename)
    maybeJson.flatMap(jsonToHexrayFile(_, filename))
  }

  private def toJson(jsonString: String, filename: String): Option[ujson.Value] = {
    Try(Option(ujson.read(jsonString))) match {
      case Success(Some(value)) => Some(value)
      case Success(None) =>
        logger.error(s"Parsing json string for $filename resulted in null return value")
        None
      case Failure(exception) =>
        logger.error(s"Parsing json string for $filename failed with exception", exception)
        None
    }

  }

  private def jsonToHexrayFile(json: ujson.Value, filename: String): Option[HexrayFile] = {
    Try(Domain.fromJson(json)) match {
      case Success(hexrayFile) => Some(hexrayFile)
      case Failure(e) =>
        logger.error(s"Failed to generate intermediate AST for $filename", e)
        None
    }
  }
}

object HexraysParser {
  private val logger = LoggerFactory.getLogger(this.getClass)
  private val PhpParserBinEnvVar = "PHP_PARSER_BIN"

  private def defaultPhpIni: String = {
    val iniContents = Source.fromResource("php.ini").getLines().mkString(System.lineSeparator())
    val tmpIni = File.newTemporaryFile(suffix = "-php.ini").deleteOnExit()
    tmpIni.writeText(iniContents)
    tmpIni.canonicalPath
  }

  private def defaultPhpParserBin: String = {
    val dir = Paths.get(this.getClass.getProtectionDomain.getCodeSource.getLocation.toURI).toAbsolutePath.toString
    val fixedDir = new java.io.File(dir.substring(0, dir.indexOf("php2cpg"))).toString
    Paths.get(fixedDir, "php2cpg", "bin", "php-parser", "php-parser.php").toAbsolutePath.toString
  }

  private def configOverrideOrDefaultPath(
                                           identifier: String,
                                           maybeOverride: Option[String],
                                           defaultValue: => String
                                         ): Option[String] = {
    val pathString = maybeOverride match {
      case Some(overridePath) if overridePath.nonEmpty =>
        logger.debug(s"Using override path for $identifier: $overridePath")
        overridePath
      case _ =>
        logger.debug(s"$identifier path not overridden. Using default: $defaultValue")
        defaultValue
    }

    File(pathString) match {
      case file if file.exists() && file.isRegularFile() => Some(file.canonicalPath)
      case _ =>
        logger.error(s"Invalid path for $identifier: $pathString")
        None
    }
  }

  private def maybePhpParserPath(config: Config): Option[String] = {
    val phpParserPathOverride = config.phpParserBin.orElse(Option(System.getenv(PhpParserBinEnvVar)))
    configOverrideOrDefaultPath("PhpParserBin", phpParserPathOverride, defaultPhpParserBin)
  }

  private def maybePhpIniPath(config: Config): Option[String] = {
    configOverrideOrDefaultPath("PhpIni", config.phpIni, defaultPhpIni)
  }

  def getParser(config: Config): Option[HexraysParser] = {
    Option(new HexraysParser(config.disableFileContent))
  }
}
