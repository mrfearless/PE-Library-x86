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
; PE_SectionSizeRaw - Get section raw size for specified section (dwSectionIndex)
; Returns: size of section or 0
;------------------------------------------------------------------------------
PE_SectionSizeRaw PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
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
    mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
    ret
PE_SectionSizeRaw ENDP

PE_LIBEND

