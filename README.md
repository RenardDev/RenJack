# RenJack
Renard Injector (PE section injection)
# Principle of operation
1. Creates and embeds two sections.
2. Fills the `.rxtext` section with NOP instructions.
3. Places the jump to the entry point at the end of the section.
4. Changes the original entry point to the beginning of the section.
5. If the payload parameters are marked, then the payload is placed at the beginning of the section.
# Usage
```
> RenJack
RenJack by Ren (zeze839@gmail.com) [Version 1.0.0.0]

[!] Warning: Usage: RenJack [/verbose:<level>] [/bdatasize:<bytes>] [/bcodesize:<bytes>] [/input:<file>] [/payload:<file>] [/savepayload] [/outputpayload:<file>] [/output:<file>]
```
```
> RenJack /?
RenJack by Ren (zeze839@gmail.com) [Version 1.0.0.0]

[!] Warning: Usage: RenJack.exe [/verbose:<level>] [/maxdatasize:<bytes>] [/maxcodesize:<bytes>] [/disabledep] [/disableaslr] [/forceguardcf] [/input:<file>] [/payload:<file>] [/savepayload] [/outputpayload:<file>] [/output:<file>]

    /verbose:<level> - Verbosity level.
    /maxdatasize - Maximum `.rxdata` size. (Default: 4096)
    /maxcodesize - Maximum `.rxtext` size. (Default: 4096)
    /disabledep - Disables DEP.
    /disableaslr - Disables ASLR.
    /forceguardcf - Force processing for GuardCF protected executable.
    /input:<file> - Input PE executable.
    /payload:<file> - Input binary (.bin) or assembly file (.asm). (Default: null)
    /savepayload - Save payload to binary file.
    /outputpayload - Output payload binary. (Default: The name of the output file with `.bin` extension.)
    /output:<file> - Output PE executable. (Default: The name of the input file with patch prefix.)
```
```
RenJack /verbose:1 /input:RenJack.exe
```
# Sources
```
https://github.com/hMihaiDavid/addscn
https://github.com/chromadevlabs/exhume
```
