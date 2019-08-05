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
; PE_HeaderRich - returns pointer to rich signature in PE file or NULL
; http://bytepointer.com/articles/the_microsoft_rich_header.htm
;------------------------------------------------------------------------------
PE_HeaderRich PROC USES EBX ECX hPE:DWORD
    LOCAL pRichSignature:DWORD
    LOCAL bFoundRich:DWORD
    LOCAL dwEndAddress:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    ; Check if we have rich header pointer saved first
    ; if so we use that, otherwise we calculate it
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PERichHeader
    .IF eax != 0
        ret
    .ENDIF
    
    Invoke PE_HeaderDOS, hPE
    .IF eax == 0
        ret
    .ENDIF
    add eax, 80h ; 128
    mov pRichSignature, eax
    
    ; Double check NT header is greater than rich sig position
    Invoke PE_HeaderNT, hPE
    .IF eax == 0
        ret
    .ENDIF
    .IF pRichSignature >= eax
        xor eax, eax
        ret
    .ENDIF
    
    ; Get address of PE in memory + filesize for max address
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    add eax, [ebx].PEINFO.PEFilesize
    mov dwEndAddress, eax
    
    ; Check for presence of 'Rich'
    mov bFoundRich, FALSE
    mov ecx, 0
    mov ebx, pRichSignature
    mov eax, 0
    .WHILE eax < 100 && ebx < dwEndAddress
        mov eax, [ebx]
        .IF eax == 68636952h ; Rich
            mov bFoundRich, TRUE
            .BREAK
        .ELSEIF eax == 0 ; Null
            .BREAK
        .ENDIF
        
        add ebx, SIZEOF DWORD
        inc ecx
        mov eax, ecx
    .ENDW
    
    ; Check if we found 'Rich'
    .IF bFoundRich == FALSE
        xor eax, eax
        ret
    .ENDIF    
    
    mov eax, pRichSignature
    ret
PE_HeaderRich ENDP



PE_LIBEND

