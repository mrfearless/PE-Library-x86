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
; PE_ImageBase - returns imagebase in eax for PE32, eax:edx for PE32+ (PE64)
;------------------------------------------------------------------------------
PE_ImageBase PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PE64
    .IF eax == TRUE
        mov eax, dword ptr [ebx].PEINFO.PE64ImageBase
        mov edx, dword ptr [ebx+4].PEINFO.PE64ImageBase
    .ELSE
        mov eax, [ebx].PEINFO.PEImageBase
        xor edx, edx
    .ENDIF
    ret
PE_ImageBase ENDP


PE_LIBEND

