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
; PE_SectionHeaderByAddr - Get section that has RVA of dwAddress
; Returns: pointer to section IMAGE_SECTION_HEADER or NULL
;------------------------------------------------------------------------------
PE_SectionHeaderByAddr PROC USES EBX EDX hPE:DWORD, dwAddress:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nCurrentSection:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwSectionSize:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PESectionCount
    mov nTotalSections, eax
    mov eax, [ebx].PEINFO.PESectionTable
    mov pCurrentSection, eax

    mov ebx, pCurrentSection
    mov edx, dwAddress
    mov eax, 0
    mov nCurrentSection, 0
    .WHILE eax < nTotalSections
        mov eax, [ebx].IMAGE_SECTION_HEADER.Misc.VirtualSize
        .IF eax == 0
            mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
        .ENDIF
        mov dwSectionSize, eax
    
        mov eax, [ebx].IMAGE_SECTION_HEADER.VirtualAddress
        .IF eax <= edx
            add eax, dwSectionSize
            .IF eax > edx
                mov eax, pCurrentSection
                ret
            .ENDIF
        .ENDIF

        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nCurrentSection
        mov eax, nCurrentSection
    .ENDW
    
    xor eax, eax
    ret
PE_SectionHeaderByAddr ENDP


PE_LIBEND

