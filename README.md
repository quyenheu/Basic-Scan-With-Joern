*INSTALLATION*


wget https://github.com/joernio/joern/releases/latest/download/joern-install.sh
chmod +x ./joern-install.sh
sudo ./joern-install.sh


*USING*


Locate install: /opt/joern


Step1: import source code

```
joern
importCode("path/to/php/project")
```


Step2: Source declaration

```
val source = cpg.call("<operator>.indexAccess").code(".*\\$_POST.*|.*\\$_GET.*|.*\\$_REQUEST.*")
```

cpg.call(): Query Call nodes in the Code Property Graph
<operator>.indexAccess: represents the array/index element access operator
-> Get all in code with access type GET[index]|POST[index]|REQUEST[index] - User input


Step3: Sink declaration

```
val sink = cpg.call("(system|shell_exec|exec|passthru|popen|proc_open)").argument(1)
```

Regex method finding
.argument(1): gets the 1st parameter of the function call


Step4: Run

```
sink.reachableByFlows(source).p
```

You can also declare a detailed function as follows:
```
def findSpecificVulnerabilities() = {
  val directConcats = cpg.call.name("$_GET", "$_POST", "$_REQUEST").map { userInput =>
    val usages = userInput.inAssignment.target.referencingIdentifiers.l
    usages.filter { usage =>
      usage.astSiblings.isCall.name("file_get_contents", "fopen", "include").exists { fileOp =>
        fileOp.argument(1).code.contains(usage.name)
      }
    }
  }.flatten.l
  
  println("Direct concatenation with user input:")
  directConcats.foreach { usage =>
    println(s"${usage.location.filename}:${usage.location.lineNumber} - ${usage.code}")
  }
}

// run
findSpecificVulnerabilities()
```

Or create a .sc file to save the code and run the command:
runScript("path/to/script/php_path_traversal.sc")

