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
; Checks the PE signatures to determine if they are valid
;------------------------------------------------------------------------------
PESignature PROC USES EBX pPEInMemory:DWORD
    mov ebx, pPEInMemory
    movzx eax, word ptr [ebx].IMAGE_DOS_HEADER.e_magic
    .IF ax == MZ_SIGNATURE
        add ebx, [ebx].IMAGE_DOS_HEADER.e_lfanew
        ; ebx is pointer to IMAGE_NT_HEADERS now
        mov eax, [ebx].IMAGE_NT_HEADERS.Signature
        .IF ax == PE_SIGNATURE
            movzx eax, word ptr [ebx].IMAGE_NT_HEADERS.OptionalHeader.Magic
            .IF ax == IMAGE_NT_OPTIONAL_HDR32_MAGIC
                mov eax, PE_ARCH_32
                ret
            .ELSEIF ax == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                mov eax, PE_ARCH_64
                ret
            .ENDIF
        .ENDIF
    .ENDIF
    mov eax, PE_INVALID
    ret
PESignature ENDP


PE_LIBEND

