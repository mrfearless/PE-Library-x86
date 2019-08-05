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
; PE_HeaderStub - returns pointer to DOS Stub
;------------------------------------------------------------------------------
PE_HeaderStub PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderDOS, hPE
    .IF eax == 0
        ret
    .ENDIF
    add eax, SIZEOF IMAGE_DOS_HEADER
    ret
PE_HeaderStub ENDP


PE_LIBEND

