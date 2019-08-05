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
; Decrease (resize) PE file. Adjustments to pointers and other data to be handled by 
; other functions. Move data before calling this.
; Returns: TRUE on success or FALSE otherwise. 
;------------------------------------------------------------------------------
PEDecreaseFileSize PROC USES EBX hPE:DWORD, dwNewSize:DWORD
    LOCAL bReadOnly:DWORD
    LOCAL PEFilesize:DWORD
    LOCAL hPEFile:DWORD
    LOCAL PEMemMapHandle:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL PENewFileSize:DWORD
    LOCAL PENewMemMapHandle:DWORD
    LOCAL PENewMemMapPtr:DWORD    
    
    .IF hPE == NULL || dwNewSize == 0
        xor eax, eax
        ret
    .ENDIF
    
    ;---------------------------------------------------
    ; Get existing file, map and view handles
    ;---------------------------------------------------
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFilesize
    .IF dwNewSize > eax ; if size is greater than existing file's size
        xor eax, eax
        ret
    .ENDIF
    mov PEFilesize, eax
    mov eax, [ebx].PEINFO.PEOpenMode
    mov bReadOnly, eax
    mov eax, [ebx].PEINFO.PEFileHandle
    mov hPEFile, eax
    mov eax, [ebx].PEINFO.PEMemMapHandle
    mov PEMemMapHandle, eax
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax    
    
    ;---------------------------------------------------
    ; Close existing mapping 
    ;---------------------------------------------------
    Invoke UnmapViewOfFile, PEMemMapPtr
    Invoke CloseHandle, PEMemMapHandle
    
    Invoke SetFilePointer, hPEFile, dwNewSize, 0, FILE_BEGIN
    Invoke SetEndOfFile, hPEFile
    Invoke FlushFileBuffers, hPEFile
    
    ;---------------------------------------------------
    ; Create file mapping of new size
    ;---------------------------------------------------
    mov eax, dwNewSize
    mov PENewFileSize, eax
    .IF bReadOnly == TRUE
        Invoke CreateFileMapping, hPEFile, NULL, PAGE_READONLY, 0, 0, NULL ; Create memory mapped file
    .ELSE
        Invoke CreateFileMapping, hPEFile, NULL, PAGE_READWRITE, 0, 0, NULL ; Create memory mapped file
    .ENDIF
    .IF eax == NULL
        xor eax, eax
        ret
    .ENDIF
    mov PENewMemMapHandle, eax
    
    ;---------------------------------------------------
    ; Map the view
    ;---------------------------------------------------
    .IF bReadOnly == TRUE
        Invoke MapViewOfFileEx, PENewMemMapHandle, FILE_MAP_READ, 0, 0, 0, NULL
    .ELSE
        Invoke MapViewOfFileEx, PENewMemMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0, NULL
    .ENDIF    
    .IF eax == NULL
        Invoke CloseHandle, PENewMemMapHandle
        xor eax, eax
        ret
    .ENDIF
    mov PENewMemMapPtr, eax    
    
    ;---------------------------------------------------
    ; Update handles and information
    ;---------------------------------------------------
    mov ebx, hPE
    mov eax, PENewMemMapPtr
    mov [ebx].PEINFO.PEMemMapPtr, eax    
    mov eax, PENewMemMapHandle
    mov [ebx].PEINFO.PEMemMapHandle, eax
    mov eax, PENewFileSize
    mov [ebx].PEINFO.PEFilesize, eax
    
    mov eax, TRUE
    ret
PEDecreaseFileSize ENDP


PE_LIBEND

