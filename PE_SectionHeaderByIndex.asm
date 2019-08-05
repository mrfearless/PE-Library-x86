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
; PE_SectionHeaderByIndex - Get section specified by dwSectionIndex
; Returns: pointer to section IMAGE_SECTION_HEADER or NULL
;------------------------------------------------------------------------------
PE_SectionHeaderByIndex PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    LOCAL pHeaderSections:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF    
    
    .IF dwSectionIndex > 96d ; max sections allowed as per MS COFF docs
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_SectionHeaderCount, hPE
    .IF dwSectionIndex >= eax
        xor eax, eax
        ret
    .ENDIF    
    
    Invoke PE_HeaderSections, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pHeaderSections, eax
    
    mov eax, dwSectionIndex
    mov ebx, SIZEOF IMAGE_SECTION_HEADER
    mul ebx
    add eax, pHeaderSections
    
    ret
PE_SectionHeaderByIndex ENDP


PE_LIBEND

