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
; PE_OffsetToRVA - convert file offset to Relative Virtual Address (RVA) 
;------------------------------------------------------------------------------
PE_OffsetToRVA PROC USES EBX hPE:DWORD, dwOffset:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nCurrentSection:DWORD
    LOCAL pCurrentSection:DWORD
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
    mov edx, dwOffset
    mov eax, 0
    mov nCurrentSection, 0
    .WHILE eax < nTotalSections
        mov eax, [ebx].IMAGE_SECTION_HEADER.PointerToRawData
        .IF eax <= edx
            mov dwPointerToRawData, eax
            mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
            add eax, dwPointerToRawData
            .IF eax > edx
                mov eax, [ebx].IMAGE_SECTION_HEADER.VirtualAddress
                mov dwVirtualAddress, eax
                
                mov ebx, dwPointerToRawData
                mov eax, edx
                sub eax, ebx
                mov edx, eax
                mov ebx, dwVirtualAddress
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
    
    xor eax, eax
    ret
PE_OffsetToRVA ENDP



PE_LIBEND

