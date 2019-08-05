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
; PE_ExportOrdinalBase - Get starting ordinal number
; Returns: starting ordinal number, or NULL
;------------------------------------------------------------------------------
PE_ExportOrdinalBase PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF

    Invoke PE_ExportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov ebx, eax ; ebx is pExportDirectoryTable
    mov eax, [ebx].IMAGE_EXPORT_DIRECTORY.nBase
    ret
PE_ExportOrdinalBase ENDP


PE_LIBEND

