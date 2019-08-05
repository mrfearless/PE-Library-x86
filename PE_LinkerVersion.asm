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
; PE_LinkerVersion - returns major and minor linker version in ax 
;------------------------------------------------------------------------------
PE_LinkerVersion PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderOptional, hPE
    mov ebx, eax
    
    Invoke PE_PE64, hPE
    .IF eax == TRUE
        movzx eax, byte ptr [ebx].IMAGE_OPTIONAL_HEADER64.MajorLinkerVersion
        mov ah, al
        movzx ebx, byte ptr [ebx].IMAGE_OPTIONAL_HEADER64.MinorLinkerVersion
        mov al, bl
    .ELSE    
        movzx eax, byte ptr [ebx].IMAGE_OPTIONAL_HEADER32.MajorLinkerVersion
        mov ah, al
        movzx ebx, byte ptr [ebx].IMAGE_OPTIONAL_HEADER32.MinorLinkerVersion
        mov al, bl
    .ENDIF
    ret
PE_LinkerVersion ENDP


PE_LIBEND

