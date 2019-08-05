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


.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_SectionInsert - Add and insert a new section.
; Returns: TRUE if successful or FALSE otherwise.
;
; Note: If function fails and error is PE_ERROR_SECTION_INS, then this is a
; fatal error in which the PE file will be closed and the hPE handle will
; be set to NULL. 
;------------------------------------------------------------------------------
PE_SectionInsert PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, dwSectionSize:DWORD, dwSectionCharacteristics:DWORD, dwSectionIndex:DWORD
    LOCAL dwNewFileSize:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF dwSectionSize == 0
        xor eax, eax
        ret
    .ENDIF
    
    ; Call PE_SectionAdd then PE_SectionMove?
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    mov eax, TRUE
    ret
PE_SectionInsert ENDP


PE_LIBEND

