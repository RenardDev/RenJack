# Warning: The project is still in development.

# RenJack
Renard Injector (PE section injection with hooks)
# Principle of operation
1. Creates and embeds two/three sections.
2. Creates `.rxhooks` for hooks. (if /hookexports is active)
3. Creates `.rxdata` for custom data.
4. Fills the `.rxtext` section with NOP instructions.
5. Places the jump to the entry point at the end of the section.
6. Changes the original entry point to the beginning of the section.
7. If the payload parameters are marked, then the payload is placed at the beginning of the section.
# Usage
```
> RenJack
RenJack by Ren (zeze839@gmail.com) [Version 2.2]

[!] Warning: Usage: RenJack [/verbose:<level>] [/maxdatasize:<bytes>] [/maxcodesize:<bytes>] [/disabledep] [/disableaslr] [/forceguardcf] [/noentrypoint] [/hookexports] [/hooksize:<bytes>] [/hookalign:<bytes>] [/input:<file>] [/payload:<file>] [/savepayload] [/outputpayload:<file>] [/output:<file>]
```
```
> RenJack /?
RenJack by Ren (zeze839@gmail.com) [Version 2.2]

[i] Usage: RenJack32 [/verbose:<level>] [/maxdatasize:<bytes>] [/maxcodesize:<bytes>] [/disabledep] [/disableaslr] [/forceguardcf] [/noentrypoint] [/hookexports] [/hooksize:<bytes>] [/hookalign:<bytes>] [/input:<file>] [/payload:<file>] [/savepayload] [/outputpayload:<file>] [/output:<file>]

    /verbose:<level> - Verbosity level.
    /maxdatasize:<bytes> - Maximum `.rxdata` size. (Default: 4096)
    /maxcodesize:<bytes> - Maximum `.rxtext` size. (Default: 4096)
    /disabledep - Disables DEP.
    /disableaslr - Disables ASLR.
    /forceguardcf - Force processing for GuardCF protected executable.
    /noentrypoint - No entry point.
    /hookexports - Hook exported functions in `.rxhooks` section.
    /hooksize:<bytes> - Hook size for one function. (Default: 16)
    /hookalign:<bytes> - Hook alignment size. (Default: 4)
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
