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
; PE_SectionName - Get section name for specified section (dwSectionIndex)
; Returns: pointer to section name or NULL
;------------------------------------------------------------------------------
PE_SectionName PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_SectionHeaderByIndex, hPE, dwSectionIndex
    .IF eax == 0
        xor eax, eax
        ret
    .ENDIF
    mov ebx, eax
    lea ebx, [ebx].IMAGE_SECTION_HEADER.Name1
    ret
PE_SectionName ENDP


PE_LIBEND

