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
; PE_RVAToOffset - convert Relative Virtual Address (RVA) to file offset
;------------------------------------------------------------------------------
PE_RVAToOffset PROC USES EBX EDX hPE:DWORD, dwRVA:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nCurrentSection:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwSectionSize:DWORD
    LOCAL dwVirtualAddress:DWORD
    LOCAL dwPointerToRawData:DWORD
    
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
    mov edx, dwRVA
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
            mov dwVirtualAddress, eax
            add eax, dwSectionSize
            .IF eax > edx
                mov eax, [ebx].IMAGE_SECTION_HEADER.PointerToRawData
                mov dwPointerToRawData, eax
                
                mov ebx, dwVirtualAddress
                mov eax, edx
                sub eax, ebx
                mov edx, eax
                mov ebx, dwPointerToRawData
                mov eax, edx
                add eax, ebx
                ret
            .ENDIF
        .ENDIF

        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nCurrentSection
        mov eax, nCurrentSection
    .ENDW
    
    mov eax, dwRVA
    ret
PE_RVAToOffset ENDP


PE_LIBEND

