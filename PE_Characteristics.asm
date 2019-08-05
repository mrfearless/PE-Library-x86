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

EXTERNDEF PE_HeaderFile     :PROTO :DWORD


.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_Characteristics - returns characteristics bit flags in eax
;------------------------------------------------------------------------------
PE_Characteristics PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderFile, hPE
    mov ebx, eax
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.Characteristics
    ret
PE_Characteristics ENDP



PE_LIBEND

