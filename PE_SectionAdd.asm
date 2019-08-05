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

EXTERNDEF PE_SetError           :PROTO :DWORD,:DWORD
EXTERNDEF PEIncreaseFileSize    :PROTO :DWORD,:DWORD

.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_SectionAdd - Add a new section header to end of section table and a new
; section of specified size and characteristics to end of PE file.
; Returns: TRUE if successful or FALSE otherwise.
;
; Note: If function fails and error is PE_ERROR_SECTION_ADD, then this is a
; fatal error in which the PE file will be closed and the hPE handle will
; be set to NULL. 
;------------------------------------------------------------------------------
PE_SectionAdd PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, dwSectionSize:DWORD, dwSectionCharacteristics:DWORD
    LOCAL dwNewFileSize:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF dwSectionSize == 0
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFilesize
    add eax, dwSectionSize
    add eax, SIZEOF IMAGE_SECTION_HEADER
    mov dwNewFileSize, eax
    Invoke PEIncreaseFileSize, hPE, dwNewFileSize
    .IF eax == TRUE
        ; increment section count in PEINFO and in PE file
        ; adjust offsets and stuff in section header
        ; move everything after section table + SIZEOF IMAGE_SECTION_HEADER
    .ELSE
        Invoke PE_SetError, hPE, PE_ERROR_SECTION_ADD
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    mov eax, TRUE
    ret
PE_SectionAdd ENDP


PE_LIBEND

