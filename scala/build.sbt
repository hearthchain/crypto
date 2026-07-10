ThisBuild / organization := "tech.hearth"
ThisBuild / version      := "0.1.0-SNAPSHOT"
ThisBuild / scalaVersion := "3.8.4"

lazy val root = (project in file("."))
  .settings(
    name := "hearth-chain",
    scalacOptions ++= Seq(
      "-deprecation",
      "-feature",
      "-unchecked",
      "-Wunused:all",
      "-source:3.8"
    ),
    // Java 22+ Foreign Function & Memory API. Stable in 22+, but the runtime
    // still prints a "restricted method" warning unless the module is enabled.
    javaOptions ++= Seq("--enable-native-access=ALL-UNNAMED"),
    // We spawn a separate JVM so javaOptions above actually take effect.
    fork := true,
    run / connectInput := true,
    libraryDependencies ++= Seq(
      "org.scalameta" %% "munit" % "1.1.1" % Test
    ),
    testFrameworks += new TestFramework("munit.Framework")
  )
