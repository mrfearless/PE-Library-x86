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
EXTERNDEF PEDecreaseFileSize    :PROTO :DWORD,:DWORD


.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_SectionDelete - Delete an existing section (by name or index)
; Returns: TRUE if successful or FALSE otherwise.
;
; Note: If function fails and error is PE_ERROR_SECTION_DEL, then this is a
; fatal error in which the PE file will be closed and the hPE handle will
; be set to NULL. 
;------------------------------------------------------------------------------
PE_SectionDelete PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, dwSectionIndex:DWORD
    LOCAL dwNewFileSize:DWORD
    LOCAL dwSectionSize:DWORD
    LOCAL nSection:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszSectionName != NULL ; section name to index 
        ; find section name
    .ELSE ; already have index
        mov eax, dwSectionIndex
    .ENDIF
    mov nSection, eax
    
    ; get existing section size
    ; 
    mov dwSectionSize, eax
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFilesize
    sub eax, dwSectionSize
    sub eax, SIZEOF IMAGE_SECTION_HEADER
    mov dwNewFileSize, eax    
    
    ; Move data down by - SIZEOF IMAGE_SECTION_HEADER
    ; adjust any stuff that needs adjusting
    
    Invoke PEDecreaseFileSize, hPE, dwNewFileSize
    .IF eax == TRUE
        ; Decrement section count in PEINFO and in PE file
        ; adjust offsets and stuff in section header
    .ELSE
        Invoke PE_SetError, hPE, PE_ERROR_SECTION_DEL
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    mov eax, TRUE
    ret
PE_SectionDelete ENDP



PE_LIBEND

