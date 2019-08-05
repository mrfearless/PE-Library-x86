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
; PE_FileName - returns in eax pointer to zero terminated string contained filename that is open or NULL if not opened
;------------------------------------------------------------------------------
PE_FileName PROC USES EBX hPE:DWORD
    LOCAL PEFilename:DWORD
    .IF hPE == NULL
        mov eax, NULL
        ret
    .ENDIF
    mov ebx, hPE
    lea eax, [ebx].PEINFO.PEFilename
    mov PEFilename, eax
    Invoke lstrlen, PEFilename
    .IF eax == 0
        mov eax, NULL
    .ELSE
        mov eax, PEFilename
    .ENDIF
    ret
PE_FileName endp


PE_LIBEND

