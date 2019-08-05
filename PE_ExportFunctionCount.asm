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
; PE_ExportFunctionCount - Get count of functions in the ExportDirectoryTable
; Returns: count of functions or 0
;------------------------------------------------------------------------------
PE_ExportFunctionCount PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF

    Invoke PE_ExportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov ebx, eax
    mov eax, [ebx].IMAGE_EXPORT_DIRECTORY.NumberOfFunctions
    ret
PE_ExportFunctionCount ENDP


PE_LIBEND

