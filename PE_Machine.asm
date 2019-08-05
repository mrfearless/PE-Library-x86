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
; PE_Machine - returns machine id in eax
;------------------------------------------------------------------------------
PE_Machine PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderFile, hPE
    mov ebx, eax
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.Machine
    ret
PE_Machine ENDP



PE_LIBEND

