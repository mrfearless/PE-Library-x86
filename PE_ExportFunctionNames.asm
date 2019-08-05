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
; PE_ExportFunctionNames - Get function names exported in the DLL
; Returns: count of functions in lpdwFunctionsList array or 0.
; On succesful return lpdwFunctionsList points to a DWORD array containing
; pointers to the function names. Use GlobalFree on this array once finished.
;------------------------------------------------------------------------------
PE_ExportFunctionNames PROC USES EBX hPE:DWORD, lpdwFunctionsList:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwExportCount:DWORD
    LOCAL pExportNamePointerTable:DWORD
    LOCAL pExportNamePointerTableEntry:DWORD
    LOCAL dwHintNameTableRVA:DWORD
    LOCAL pNameList:DWORD
    LOCAL pNameListNextFunction:DWORD
    LOCAL dwNameListSize:DWORD
    LOCAL nExport:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpdwFunctionsList == 0
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    
    Invoke PE_ExportNameCount, hPE
    .IF eax == NULL
        ret
    .ENDIF
    mov dwExportCount, eax
    
    Invoke PE_ExportNamePointerTable, hPE
    .IF eax == NULL
        ret
    .ENDIF
    mov pExportNamePointerTable, eax
    mov pExportNamePointerTableEntry, eax
    
    ; calc max name list string size
    mov eax, dwExportCount
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

    mov ebx, pExportNamePointerTableEntry
    mov nExport, 0
    mov eax, 0
    .WHILE eax < dwExportCount
        mov eax, [ebx] ; get rva pointer to function string 
        Invoke PE_RVAToOffset, hPE, eax
        .IF eax == 0
            ret
        .ENDIF    
        add eax, PEMemMapPtr ; eax is pointer to function string
        mov ebx, pNameListNextFunction
        mov [ebx], eax ; store pointer to function string in our array

        add pNameListNextFunction, SIZEOF DWORD
        add pExportNamePointerTableEntry, SIZEOF DWORD ; pointers are always 32bits

        mov ebx, pExportNamePointerTableEntry
        inc nExport
        mov eax, nExport
    .ENDW
    
    mov ebx, lpdwFunctionsList
    mov eax, pNameList
    mov [ebx], eax
    
    mov eax, dwExportCount
    ret
PE_ExportFunctionNames ENDP



PE_LIBEND

