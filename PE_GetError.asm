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
; PE_GetError
;------------------------------------------------------------------------------
PE_GetError PROC
    mov eax, PELIB_ErrorNo
    ret
PE_GetError ENDP


PE_LIBEND

