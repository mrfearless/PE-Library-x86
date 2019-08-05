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

EXTERNDEF PELIB_ErrorNo :DWORD

.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_SetError
;------------------------------------------------------------------------------
PE_SetError PROC USES EBX hPE:DWORD, dwError:DWORD
    .IF hPE != NULL && dwError != PE_ERROR_SUCCESS
        mov ebx, hPE
        mov ebx, [ebx].PEINFO.PEHandle 
        .IF ebx != 0
            mov eax, 0 ; null out hPE handle if it exists
            mov [ebx], eax
        .ENDIF
    .ENDIF
    mov eax, dwError
    mov PELIB_ErrorNo, eax
    ret
PE_SetError ENDP


PE_LIBEND

