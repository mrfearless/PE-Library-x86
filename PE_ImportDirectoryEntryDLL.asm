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
; PE_ImportDirectoryEntryDLL - Get DLL name for specified ImportDirectoryTable 
; Entry (dwImportDirectoryEntryIndex)
; Returns: address of zero terminated DLL name string, or NULL
;------------------------------------------------------------------------------
PE_ImportDirectoryEntryDLL PROC USES EBX hPE:DWORD, dwImportDirectoryEntryIndex:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pImportDirectoryTable:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
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
    
    mov eax, [ebx].IMAGE_IMPORT_DESCRIPTOR.Name1
    Invoke PE_RVAToOffset, hPE, eax
    add eax, PEMemMapPtr
    ; eax has pointer to DLL name
    ret
PE_ImportDirectoryEntryDLL ENDP


PE_LIBEND

