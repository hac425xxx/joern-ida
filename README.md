将 IDA Hexray AST 转化为 CPG 进行分析



首先使用 ida-extractor.zip 提取二进制的 AST

然后利用 Joern 生成 cpg

```
joern> importCode
val res1:
  io.joern.console.cpgcreation.ImportCode[io.joern.joerncli.console.JoernProject
    ] = Type `importCode.<language>` to run a specific language frontend

_________________________________________________________________________________
| name       | description                                            | available|
|================================================================================|
| c          | Eclipse CDT Based Frontend for C/C++                   | true     |
| cpp        | Eclipse CDT Based Frontend for C/C++                   | true     |
| ghidra     | ghidra reverse engineering frontend                    | true     |
| kotlin     | Kotlin Source Frontend                                 | true     |
| java       | Java Source Frontend                                   | true     |
| jvm        | Java/Dalvik Bytecode Frontend (based on SOOT's jimple) | true     |
| javascript | Javascript Source Frontend                             | true     |
| jssrc      | Javascript/Typescript Source Frontend based on astgen  | true     |
| swiftsrc   | Swift Source Frontend based on swiftastgen             | true     |
| golang     | Golang Source Frontend                                 | true     |
| llvm       | LLVM Bitcode Frontend                                  | false    |
| php        | PHP source frontend                                    | true     |
| ida        | IDA Hexray AST frontend                                | true     |
| python     | Python Source Frontend                                 | true     |
| csharp     | C# Source Frontend (Roslyn)                            | false    |
| ruby       | Ruby source frontend                                   | true     |
| ruby       | Ruby source deprecated frontend                        | true     |


joern> importCode.ida("f:\\sca\\binary\\ida_ast_dir")
```



或者手动提取 cpg

```
ida2cpg.bat -J-Xmx30208m astDir
```


