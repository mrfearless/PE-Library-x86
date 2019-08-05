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

EXTERNDEF PE_HeaderOptional     :PROTO :DWORD
EXTERNDEF PE_PE64               :PROTO :DWORD

.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_ImageBase - returns size of image in eax
;------------------------------------------------------------------------------
PE_SizeOfImage PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderOptional, hPE
    mov ebx, eax
    
    Invoke PE_PE64, hPE
    .IF eax == TRUE
        mov eax, [ebx].IMAGE_OPTIONAL_HEADER64.SizeOfImage
    .ELSE
        mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.SizeOfImage
    .ENDIF
    ret
PE_SizeOfImage ENDP


PE_LIBEND

