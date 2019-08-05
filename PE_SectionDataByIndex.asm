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
; PE_SectionDataByIndex - Get pointer to section's raw data 
; Returns: pointer to section data or null
;------------------------------------------------------------------------------
PE_SectionDataByIndex PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD, lpdwSectionDataSize:DWORD
    LOCAL pSectionHeader:DWORD
    LOCAL pSectionData:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwSizeSectionData:DWORD
    
    Invoke PE_SectionHeaderByIndex, hPE, dwSectionIndex
    .IF eax == 0
        ret
    .ENDIF
    mov pSectionHeader, eax
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    
    mov ebx, pSectionHeader
    mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
    ;.IF eax == 0
    ;    mov eax, [ebx].IMAGE_SECTION_HEADER.Misc.VirtualSize
    ;.ENDIF
    mov dwSizeSectionData, eax
    mov eax, [ebx].IMAGE_SECTION_HEADER.PointerToRawData
    add eax, PEMemMapPtr
    mov pSectionData, eax
    
    .IF lpdwSectionDataSize != 0
        mov ebx, lpdwSectionDataSize
        mov eax, dwSizeSectionData
        mov [ebx], eax
    .ENDIF

    mov eax, pSectionData
    ret
PE_SectionDataByIndex ENDP


PE_LIBEND

