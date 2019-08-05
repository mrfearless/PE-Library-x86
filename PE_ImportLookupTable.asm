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
; PE_ImportLookupTable - Get pointer to Import Lookup Table (array of DWORDs) 
; for the specified ImportDirectoryTable entry (dwImportDirectoryEntryIndex)
; Returns: pointer to Import Lookup Table, or 0
;------------------------------------------------------------------------------
PE_ImportLookupTable PROC USES EBX hPE:DWORD, dwImportDirectoryEntryIndex:DWORD, lpdwImportCount:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pImportDirectoryTable:DWORD
    LOCAL pImportLookupTable:DWORD
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
    mov eax, [ebx].PEINFO.PEImportDirectoryCount
    .IF dwImportDirectoryEntryIndex >= eax
        mov eax, 0
        ret
    .ENDIF
    
    Invoke PE_ImportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pImportDirectoryTable, eax

    ; calc specific ImportDirectoryTable entry offset
    mov eax, dwImportDirectoryEntryIndex
    mov ebx, SIZEOF IMAGE_IMPORT_DESCRIPTOR
    mul ebx
    add eax, pImportDirectoryTable
    mov ebx, eax ; offset to specific entry in ebx
    
    mov eax, [ebx].IMAGE_IMPORT_DESCRIPTOR.Characteristics
    Invoke PE_RVAToOffset, hPE, eax
    add eax, PEMemMapPtr ; eax has pointer to Import Lookup Table for this DLL entry
    mov pImportLookupTable, eax

    .IF lpdwImportCount != NULL ; loop and count how many functions exported
        mov eax, 0
        mov ebx, pImportLookupTable
        .IF bPE64 == TRUE
            .WHILE dword ptr [ebx] != 0 && dword ptr [ebx+4] != 0
                inc eax
                add ebx, SIZEOF QWORD ; array of QWORDS each pointing to an IMAGE_IMPORT_BY_NAME structure
            .ENDW
        .ELSE
            .WHILE dword ptr [ebx] != 0
                inc eax
                add ebx, SIZEOF DWORD ; array of DWORDS each pointing to an IMAGE_IMPORT_BY_NAME structure
            .ENDW
        .ENDIF
        mov ebx, lpdwImportCount
        mov [ebx], eax
    .ENDIF
    
    mov eax, pImportLookupTable
    ret
PE_ImportLookupTable ENDP



PE_LIBEND

