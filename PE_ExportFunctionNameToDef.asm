;==============================================================================
;
; PE Library
;
; Copyright (c) 2019 by fearless
;
; http://github.com/mrfearless
;
;==============================================================================
.686
.MMX
.XMM
.model flat,stdcall
option casemap:none

include windows.inc
include user32.inc
include kernel32.inc

includelib user32.lib
includelib kernel32.lib

include PE.inc

.DATA
DEFEXT                      DB '.def',0
DEFLIBRARY                  DB 'LIBRARY ',0
dwLenDEFLIBRARY             DD ($-DEFLIBRARY)-1
DEFEXPORTS                  DB 'EXPORTS',13,10,0
dwLenDEFEXPORTS             DD ($-DEFEXPORTS)-1
DEFINDENT                   DB '    ',0
dwLenDEFINDENT              DD ($-DEFINDENT)-1
DEFCRLF                     DB 13,10,0
dwLenDEFCRLF                DD ($-DEFCRLF)-1


.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_ExportFunctionNameToDef - Creates a .DEF file from export functions 
;------------------------------------------------------------------------------
PE_ExportFunctionNameToDef PROC USES EBX hPE:DWORD, lpszDefFilename:DWORD, bUseFilename:DWORD, bRemoveUnderscore:DWORD
    LOCAL pExportFunctionNamesList:DWORD
    LOCAL pExportName:DWORD
    LOCAL nExportName:DWORD
    LOCAL dwExportNameCount:DWORD
    LOCAL lpszExportName:DWORD
    LOCAL lpszExportDllName:DWORD
    LOCAL hDefFile:DWORD
    LOCAL dwNumberOfBytesToWrite:DWORD
    LOCAL dwNumberOfBytesWritten:DWORD
    LOCAL szDefFilename[MAX_PATH]:BYTE
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszDefFilename == NULL
        ; create def file based on export name (usually a .dll) 
        lea ebx, szDefFilename
        mov byte ptr [ebx], '.'
        mov byte ptr [ebx+1], '\'
        .IF bUseFilename == TRUE
            Invoke PE_FileNameOnly, hPE, Addr szDefFilename+2
            Invoke lstrcat, Addr szDefFilename, Addr DEFEXT
        .ELSE ; use internal module name instead
            Invoke PE_ExportDLLName, hPE
            Invoke lstrcpyn, Addr szDefFilename+2, eax, MAX_PATH
            Invoke lstrlen, Addr szDefFilename
            lea ebx, szDefFilename
            add ebx, eax
            sub ebx, 4
            mov eax, [ebx]
            .IF eax == 'LLD.' || eax == 'lld.' || eax == 'EXE.' || eax == 'exe.'
                mov byte ptr [ebx+1], 'd'
                mov byte ptr [ebx+2], 'e'
                mov byte ptr [ebx+3], 'f'
                mov byte ptr [ebx+4], 0
            .ELSE
                xor eax, eax
                ret
            .ENDIF
        .ENDIF
    .ENDIF
    
    Invoke PE_ExportNameCount, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov dwExportNameCount, eax
    
    Invoke PE_ExportFunctionNames, hPE, Addr pExportFunctionNamesList
    .IF eax == 0
        ret
    .ENDIF
    
    mov eax, pExportFunctionNamesList
    mov pExportName, eax
    
    ; Create DEF file
    .IF lpszDefFilename == NULL
        Invoke CreateFile, Addr szDefFilename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    .ELSE
        Invoke CreateFile, lpszDefFilename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    .ENDIF
    .IF eax == INVALID_HANDLE_VALUE
        xor eax, eax
        ret
    .ENDIF
    mov hDefFile, eax
    
    ; Write out LIBRARY and EXPORTS to DEF file
    Invoke WriteFile, hDefFile, Addr DEFLIBRARY, dwLenDEFLIBRARY, Addr dwNumberOfBytesWritten, NULL
    .IF bUseFilename == TRUE
        Invoke PE_FileNameOnly, hPE, Addr szDefFilename ; reuse szDefFilename buffer
        Invoke lstrlen, Addr szDefFilename
        mov dwNumberOfBytesToWrite, eax
        Invoke WriteFile, hDefFile, Addr szDefFilename, dwNumberOfBytesToWrite, Addr dwNumberOfBytesWritten, NULL
    .ELSE
        Invoke PE_ExportDLLName, hPE
        mov lpszExportDllName, eax
        Invoke lstrlen, lpszExportDllName
        mov dwNumberOfBytesToWrite, eax
        Invoke WriteFile, hDefFile, lpszExportDllName, dwNumberOfBytesToWrite, Addr dwNumberOfBytesWritten, NULL
    .ENDIF
    Invoke WriteFile, hDefFile, Addr DEFCRLF, dwLenDEFCRLF, Addr dwNumberOfBytesWritten, NULL
    Invoke WriteFile, hDefFile, Addr DEFEXPORTS, dwLenDEFEXPORTS, Addr dwNumberOfBytesWritten, NULL
    
    mov nExportName, 0
    mov eax, 0
    .WHILE eax < dwExportNameCount
        mov ebx, pExportName
        mov eax, [ebx]
        mov lpszExportName, eax
        
        .IF bRemoveUnderscore == TRUE
            mov ebx, lpszExportName
            movzx eax, byte ptr [ebx]
            .IF al == '_'
                inc lpszExportName
            .ENDIF
        .ENDIF
        
        ; Write out function name to DEF file
        Invoke WriteFile, hDefFile, Addr DEFINDENT, dwLenDEFINDENT, Addr dwNumberOfBytesWritten, NULL
        Invoke lstrlen, lpszExportName
        mov dwNumberOfBytesToWrite, eax
        Invoke WriteFile, hDefFile, lpszExportName, dwNumberOfBytesToWrite, Addr dwNumberOfBytesWritten, NULL
        Invoke WriteFile, hDefFile, Addr DEFCRLF, dwLenDEFCRLF, Addr dwNumberOfBytesWritten, NULL
        
        add pExportName, SIZEOF DWORD
        inc nExportName
        mov eax, nExportName
    .ENDW
    
    ; Close DEF File
    Invoke CloseHandle, hDefFile
    
    mov eax, TRUE
    ret
PE_ExportFunctionNameToDef ENDP



PE_LIBEND



