organization := "info.cmlubinski"

version := "0.1"

name := "Lift Encrypted Fields 2.4"

crossScalaVersions := Seq("2.9.1", "2.8.1")

//  Lift
libraryDependencies += "net.liftweb" %% "lift-record" % "2.4"

//  Bouncy Castle
libraryDependencies += "org.bouncycastle" % "bcprov-jdk16" % "1.46"
