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

EXTERNDEF PE_DllCharacteristics        :PROTO :DWORD


.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_ASLR - returns TRUE if ASLR is enabled or FALSE otherwise
;------------------------------------------------------------------------------
PE_ASLR PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_DllCharacteristics, hPE
    .IF eax == 0
        ret
    .ENDIF
    and eax, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    .IF eax == IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        mov eax, TRUE
    .ELSE
        xor eax, eax
    .ENDIF
    ret
PE_ASLR ENDP


PE_LIBEND

