lazy val `play-webgoat` = (project in file(".")).enablePlugins(PlayScala)

name := "play-webgoat"
version := "1.0"

crossScalaVersions := Seq("2.13.18", "3.3.7")
scalaVersion := crossScalaVersions.value.head // tc-skip

libraryDependencies ++= Seq(guice, ws, jdbc)
scalacOptions ++= Seq(
  // "-unchecked", "-deprecation" // Set by Play already
  "-feature", "-Werror",
)
scalacOptions ++= (CrossVersion.partialVersion(scalaVersion.value) match {
  case Some((2, _)) => Seq("-Xlint:-unused,_")
  case _ => Seq()
})
libraryDependencies += "org.playframework.anorm" %% "anorm" % "2.7.0"
libraryDependencies += "com.h2database" % "h2" % "2.2.224"
libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % "2.6.21",
  "com.typesafe.akka" %% "akka-serialization-jackson" % "2.6.21"
)
libraryDependencies += "org.scala-lang" % "scala-compiler" % scalaVersion.value
libraryDependencies += "org.mvel" % "mvel2" % "2.5.2.Final"
libraryDependencies += "org.springframework" % "spring-expression" % "5.3.31"
libraryDependencies += "org.springframework.ldap" % "spring-ldap-core" % "2.4.0"