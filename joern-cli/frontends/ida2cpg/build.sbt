import scala.sys.process._
import scala.util.Properties.isWin
import better.files.File

name := "ida2cpg"

dependsOn(Projects.dataflowengineoss % "compile->compile;test->test", Projects.x2cpg % "compile->compile;test->test")

libraryDependencies ++= Seq(
  "com.lihaoyi"   %% "upickle"           % Versions.upickle,
  "com.lihaoyi"   %% "ujson"             % Versions.upickle,
  "io.shiftleft"  %% "codepropertygraph" % Versions.cpg,
  "org.scalatest" %% "scalatest"         % Versions.scalatest % Test,
  "io.circe"      %% "circe-core"        % Versions.circe
)


Compile / compile := ((Compile / compile)).value

enablePlugins(JavaAppPackaging, LauncherJarPlugin)
Global / onChangedBuildSource := ReloadOnSourceChanges
