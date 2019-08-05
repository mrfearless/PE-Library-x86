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
; PE_SectionMove - Move section (by name or index) to section (by name or index)
; Returns: TRUE if successful or FALSE otherwise.
;
; Note: If function fails and error is PE_ERROR_SECTION_MOVE, then this is a
; fatal error in which the PE file will be closed and the hPE handle will
; be set to NULL. 
;------------------------------------------------------------------------------
PE_SectionMove PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, dwSectionIndex:DWORD, lpszSectionNameToMoveTo:DWORD, dwSectionIndexToMoveTo:DWORD
    LOCAL nSectionFrom:DWORD
    LOCAL nSectionTo:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszSectionName != NULL
        
    .ELSE
        mov eax, dwSectionIndex
    .ENDIF
    mov nSectionFrom, eax
    
    .IF lpszSectionNameToMoveTo != NULL
        
    .ELSE
        mov eax, dwSectionIndexToMoveTo
    .ENDIF
    mov nSectionTo, eax    
    
    ; check section indexes are within section count and are not same
    
    ; calc blocks of memory to copy/move
     
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    mov eax, TRUE
    ret
PE_SectionMove ENDP


PE_LIBEND

