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
; PE_RichSignatureDecode - Decodes rich signature and returns a block of 
; memory, pointed to by the lpDecodedRichSignature parameter. lpdwSize var
; will contains size of decoded block on succesful return. Use GlobalFree
; once you have done with the decoded block.
;
; lpDecodedRichSignature can be null if you want to just return size of rich
; signature in lpdwSize
;
; Code adapted from Daniel Pistelli: https://ntcore.com/files/richsign.htm
;
; Returns: TRUE or FALSE
;------------------------------------------------------------------------------
PE_RichSignatureDecode PROC USES EBX ECX EDX hPE:DWORD, lpdwDecodedRichSignature:DWORD, lpdwSize:DWORD
    LOCAL pHeaderRich:DWORD
    LOCAL pRSEntry:DWORD
    LOCAL pRSNewData:DWORD
    LOCAL pRSNewEntry:DWORD
    LOCAL nSignDwords:DWORD
    LOCAL dwMask:DWORD
    LOCAL dwSize:DWORD
    LOCAL dwEndAddress:DWORD
    
    .IF lpdwDecodedRichSignature == 0 && lpdwSize == 0
        xor eax, eax
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
    
    ; read xor mask
    mov eax, dword ptr [ebx+4]
    mov dwMask, eax
    
    ; alloc memory for decrypted block
    mov eax, nSignDwords
    inc eax
    mov ebx, SIZEOF DWORD
    mul ebx
    mov dwSize, eax
    
    .IF lpdwDecodedRichSignature != 0
        Invoke GlobalAlloc, GMEM_FIXED or GMEM_ZEROINIT, dwSize
        mov pRSNewData, eax
        mov pRSNewEntry, eax
        mov edx, pRSNewEntry
        
        ; decrypt signature
        mov ebx, pHeaderRich
        mov pRSEntry, ebx
        mov ecx, 0
        mov eax, 0
        .WHILE eax < nSignDwords && ebx < dwEndAddress
            mov eax, [ebx]      ; read pRSEntry DWORD
            mov ebx, dwMask
            xor eax, ebx        ; decrypt (xor) with mask
            mov [edx], eax      ; store DWORD in pRSNewEntry
            
            add pRSNewEntry, SIZEOF DWORD
            add pRSEntry, SIZEOF DWORD
            mov ebx, pRSEntry
            mov edx, pRSNewEntry
            inc ecx
            mov eax, ecx
        .ENDW
        
        ; write new mask for decrypted signature
        mov dword ptr [edx+4], 0FFFFFFFFh
        
        ; return decrypted block and size
        mov ebx, lpdwDecodedRichSignature
        mov eax, pRSNewData
        mov [ebx], eax
    .ENDIF
    
    .IF lpdwSize != NULL
        mov ebx, lpdwSize
        mov eax, dwSize
        mov [ebx], eax
    .ENDIF 

    mov eax, TRUE
    ret
PE_RichSignatureDecode ENDP



PE_LIBEND

