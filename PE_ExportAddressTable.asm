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
; PE_ExportAddressTable
;------------------------------------------------------------------------------
PE_ExportAddressTable PROC USES EBX hPE:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pExportDirectoryTable:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax

    Invoke PE_ExportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov ebx, eax ; ebx is pExportDirectoryTable
    
    mov eax, [ebx].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    Invoke PE_RVAToOffset, hPE, eax
    add eax, PEMemMapPtr
    ; eax has pointer to Export Address Table RVA
    ret
PE_ExportAddressTable ENDP


PE_LIBEND

