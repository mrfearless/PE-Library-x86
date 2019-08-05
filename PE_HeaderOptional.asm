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
; PE_HeaderOptional - returns pointer to IMAGE_OPTIONAL_HEADER (32/64)
;------------------------------------------------------------------------------
PE_HeaderOptional PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEOptionalHeader
    ; eax points to IMAGE_OPTIONAL_HEADER (32/64)
    ret
PE_HeaderOptional ENDP


PE_LIBEND

