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
; PE_SectionHeaderByName - Get section specified by lpszSectionName
; Returns: pointer to section IMAGE_SECTION_HEADER or NULL
;------------------------------------------------------------------------------
PE_SectionHeaderByName PROC USES EBX hPE:DWORD, lpszSectionName:DWORD
    LOCAL pHeaderSections:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL lpszName:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nSection:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszSectionName == NULL
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_HeaderSections, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pHeaderSections, eax
    mov pCurrentSection, eax
    
    Invoke PE_SectionHeaderCount, hPE
    mov nTotalSections, eax
    mov ebx, pCurrentSection
    mov nSection, 0
    mov eax, 0
    .WHILE eax < nTotalSections    
        lea eax, [ebx].IMAGE_SECTION_HEADER.Name1
        mov lpszName, eax
        Invoke lstrcmp, lpszName, lpszSectionName
        .IF eax == 0 ; match
            mov eax, pCurrentSection
            ret
        .ENDIF

        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nSection
        mov eax, nSection
    .ENDW
    
    xor eax, eax
    ret
PE_SectionHeaderByName ENDP



PE_LIBEND

