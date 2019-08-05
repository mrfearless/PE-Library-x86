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
; PE_RichSignatureCompIDs - returns total compids in rich signature
;------------------------------------------------------------------------------
PE_RichSignatureCompIDs PROC USES EBX ECX hPE:DWORD
    LOCAL pHeaderRich:DWORD
    LOCAL dwEndAddress:DWORD
    LOCAL nSignDwords:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    ; check if we have total compids first
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PERichCompIDs
    .IF eax != 0
        ret
    .ENDIF
    
    Invoke PE_HeaderRich, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pHeaderRich, eax

    ; Get address of PE in memory + filesize for max address
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    add eax, [ebx].PEINFO.PEFilesize
    mov dwEndAddress, eax    
    
    ; Loop through rich signature location
    ; count no of dwords till we hit max no
    ; or null, or 'Rich'.
    mov ebx, pHeaderRich
    add ebx, 16d ; skip past DanS and padding
    mov nSignDwords, 0
    mov ecx, 0
    mov eax, 0
    .WHILE eax < 100 && ebx < dwEndAddress
        mov eax, [ebx]
        .IF eax == 68636952h ; Rich
            mov eax, ecx
            mov nSignDwords, eax
            .BREAK
        .ELSEIF eax == 0 ; Null
            .BREAK
        .ENDIF
        
        add ebx, SIZEOF DWORD
        inc ecx
        mov eax, ecx
    .ENDW
    
    ; Check if we got anything
    .IF nSignDwords == 0
        xor eax, eax
        ret
    .ENDIF
    
    mov eax, nSignDwords
    shr eax, 1 ; div by 2
    ret
PE_RichSignatureCompIDs ENDP


PE_LIBEND

