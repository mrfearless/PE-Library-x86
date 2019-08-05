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
; PE_ImportDirectoryEntryFunctions - Get function names for a DLL
; Returns: count of functions in lpdwFunctionsList array or 0.
; On succesful return lpdwFunctionsList points to a DWORD array containing
; pointers to the function names. Use GlobalFree on this array once finished.
;------------------------------------------------------------------------------
PE_ImportDirectoryEntryFunctions PROC USES EBX hPE:DWORD, dwImportDirectoryEntryIndex:DWORD, lpdwFunctionsList:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwImportCount:DWORD
    LOCAL pImportLookupTable:DWORD
    LOCAL pImportLookupTableEntry:DWORD
    LOCAL dwHintNameTableRVA:DWORD
    LOCAL pNameList:DWORD
    LOCAL pNameListNextFunction:DWORD
    LOCAL dwNameListSize:DWORD
    LOCAL bPE64:DWORD
    LOCAL nImport:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpdwFunctionsList == 0
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
    mov pImportLookupTableEntry, eax
    
    ; calc max name list string size
    mov eax, dwImportCount
    inc eax
    mov ebx, SIZEOF DWORD
    mul ebx
    mov dwNameListSize, eax
    
    Invoke GlobalAlloc, GMEM_FIXED or GMEM_ZEROINIT, dwNameListSize
    .IF eax == NULL
        ret
    .ENDIF
    mov pNameList, eax
    mov pNameListNextFunction, eax

    mov ebx, pImportLookupTableEntry
    mov nImport, 0
    mov eax, 0
    .WHILE eax < dwImportCount
        .IF bPE64 == TRUE
            mov eax, [ebx+4]
        .ELSE
            mov eax, [ebx]
        .ENDIF
        mov dwHintNameTableRVA, eax
        and eax, 80000000h
        .IF eax == 1 ; import by ordinal
            ; do something
        .ENDIF
        
        Invoke PE_RVAToOffset, hPE, dwHintNameTableRVA
        .IF eax == 0
            ret
        .ENDIF    
        add eax, PEMemMapPtr
        mov ebx, eax
        lea eax, [ebx].IMAGE_IMPORT_BY_NAME.Name1
        mov ebx, pNameListNextFunction
        mov [ebx], eax

        add pNameListNextFunction, SIZEOF DWORD
        .IF bPE64 == TRUE
            add pImportLookupTableEntry, SIZEOF QWORD
        .ELSE
            add pImportLookupTableEntry, SIZEOF DWORD
        .ENDIF
        mov ebx, pImportLookupTableEntry
        inc nImport
        mov eax, nImport
    .ENDW
    
    mov ebx, lpdwFunctionsList
    mov eax, pNameList
    mov [ebx], eax
    
    mov eax, dwImportCount
    ret
PE_ImportDirectoryEntryFunctions ENDP



PE_LIBEND

