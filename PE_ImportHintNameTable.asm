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


.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_ImportHintNameTable - Get pointer to a Hint Name Table for a specific
; function as specified by dwFunctionIndex parameter for a specific DLL 
; (as specified by dwImportDirectoryEntryIndex).
; If import by ordinal then will return will be 0
; Returns: pointer to IMAGE_IMPORT_BY_NAME for specific function or 0
;------------------------------------------------------------------------------
PE_ImportHintNameTable PROC USES EBX hPE:DWORD, dwImportDirectoryEntryIndex:DWORD, dwFunctionIndex:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwImportCount:DWORD
    LOCAL pImportLookupTable:DWORD
    LOCAL pImportLookupTableEntry:DWORD
    LOCAL dwHintNameTableRVA:DWORD
    LOCAL bPE64:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PE64
    mov bPE64, eax
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    
    Invoke PE_ImportLookupTable, hPE, dwImportDirectoryEntryIndex, Addr dwImportCount
    .IF eax == NULL
        ret
    .ENDIF
    mov pImportLookupTable, eax
    
    mov eax, dwFunctionIndex
    .IF eax > dwImportCount
        xor eax, eax
        ret
    .ENDIF
    .IF bPE64 == TRUE
        mov ebx, SIZEOF QWORD
    .ELSE
        mov ebx, SIZEOF DWORD
    .ENDIF
    mul ebx
    add eax, pImportLookupTable
    mov pImportLookupTableEntry, eax
    
    mov ebx, pImportLookupTableEntry
    .IF bPE64 == TRUE
        mov eax, [ebx+4]
    .ELSE
        mov eax, [ebx]
    .ENDIF
    mov dwHintNameTableRVA, eax
    and eax, 80000000h
    .IF eax == 1 ; import by ordinal
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_RVAToOffset, hPE, dwHintNameTableRVA
    .IF eax == 0
        ret
    .ENDIF    
    add eax, PEMemMapPtr
    ; eax points to IMAGE_IMPORT_BY_NAME for this function for this import directory entry
    
    
    ret
PE_ImportHintNameTable ENDP


PE_LIBEND

