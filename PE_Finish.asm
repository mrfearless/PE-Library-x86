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
; PE_Finish - Frees up hPE if PE was processed from memory directly with a call
; to PE_Analyze. If PE was opened as a file via PE_OpenFile, then PE_CloseFile 
; should be used instead of this function.
; Returns: None
;------------------------------------------------------------------------------
PE_Finish PROC USES EBX hPE:DWORD

    IFDEF DEBUG32
    PrintText 'PE_Finish'
    ENDIF
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov ebx, [ebx].PEINFO.PEHandle
    .IF ebx != 0
        mov eax, 0 ; null out hPE handle if it exists
        mov [ebx], eax
    .ENDIF
        
    mov eax, hPE
    .IF eax != NULL
        Invoke GlobalFree, eax
    .ENDIF
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    xor eax, eax
    ret
PE_Finish ENDP


PE_LIBEND

