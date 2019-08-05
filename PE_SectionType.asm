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
; PE_SectionType - Get section characteristics for specified 
; section (dwSectionIndex) and return type of section: executable, writable 
; data, read only data, uninitialized data
; Returns: 0 for unknow, 1 for EX, 2 for WD, 3 for RD, 4 for 0D
;------------------------------------------------------------------------------
PE_SectionType PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    LOCAL Characteristics:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_SectionCharacteristics, hPE, dwSectionIndex
    .IF eax == 0
        ret
    .ENDIF
    mov Characteristics, eax
    
    and eax, (IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE)
    .IF eax == (IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE)
        mov eax, 1 ; code execution
        ret
    .ENDIF
    
    mov eax, Characteristics
    and eax, (IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE)
    .IF eax == (IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE)
        mov eax, 2 ; writable data
        ret
    .ENDIF
    
    mov eax, Characteristics
    and eax, (IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ)
    .IF eax == (IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ)
        mov eax, 3 ; readonly data
        ret
    .ENDIF
    
    mov eax, Characteristics
    and eax, (IMAGE_SCN_CNT_UNINITIALIZED_DATA or IMAGE_SCN_MEM_READ)
    .IF eax == (IMAGE_SCN_CNT_UNINITIALIZED_DATA or IMAGE_SCN_MEM_READ)
        mov eax, 4 ; uninitialized data like .bss
        ret
    .ENDIF
    
    ret
PE_SectionType ENDP


PE_LIBEND

