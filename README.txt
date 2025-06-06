SIGPacker is a polymorphic packer.

this was/is a project that only aims to improve my knowledge of the PE structure and x86 assembly.

this project uses resources/code from these 2 projects:
 - Zydis,  Parsing and x86 assembler generation (MIT)
 - wine,   Structures and defines (LGPL)

So you must also respect these licenses.

=== TODO LIST ===

general
  [X] input file
  [X] output file

x86
  [ ] polymorphism
    [X] detect commutative instructions
    [X] move instructions
        [X] commutatives
        [X] detect jump destinations
        [X] patch jumps
    [ ] generate junk code
      [ ] remove nops
      [ ] add junk instructions
    [X] find alternative instructions

PE
  [X] parse
  [X] check it is an executable
  [X] build
  [X] pack functions
    [X] default symbol blacklist
    [X] symbol whitelist
    [X] symbol blacklist
    [X] detect executable sections
    [X] list symbols
  [ ] pack data sections
    [ ] detect _must encrypt_ areas
      [X] x64
      [X] x86
      [ ] using relocations (might be more accurate for x86)
    [X] encryption
    [ ] decrypt payloads
      [ ] x86
        [X] payload
        [X] injection
        [ ] polymorphism
      [ ] x64
        [X] payload
        [X] injection
        [ ] polymorphism
  [ ] imports
    [ ] hide imports
      [ ] replace import name
        [X] function whitelist
        [ ] respect import name order
        [ ] delete import if can't find suitable replacement
      [X] PEB walking
        [X] x86
        [X] x64
      [X] polymorphism