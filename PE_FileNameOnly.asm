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

EXTERNDEF PEJustFname   :PROTO :DWORD,:DWORD


.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_FileNameOnly - returns in eax true or false if it managed to pass to the 
; buffer pointed at lpszFileNameOnly, the stripped filename without extension
;------------------------------------------------------------------------------
PE_FileNameOnly PROC hPE:DWORD, lpszFileNameOnly:DWORD
    Invoke PE_FileName, hPE
    .IF eax == NULL
        mov eax, FALSE
        ret
    .ENDIF
    Invoke PEJustFname, eax, lpszFileNameOnly
    mov eax, TRUE
    ret
PE_FileNameOnly endp



PE_LIBEND

