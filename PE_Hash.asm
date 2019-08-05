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
; PE_Hash - Hash PE file contents into buffer provided by lpHashBytes param
; and return size of returned hash bytes in lpdwHashSize if not 0.
; lpHashBytes can be 0 if we want to return the size only in lpdwHashSize for
; allocating correct size of buffer, otherwise ensure lpHashBytes is large
; enough for the hash type.
; dwHashType: HASH_MD5, HASH_SHA1, or HASH_SHA256
;
; Code adapted from Michael B: 
; https://github.com/DownWithUp/CommandPrompt-Add-Ons/blob/master/FASM/SHA256.asm
; Returns: TRUE or FALSE
;------------------------------------------------------------------------------
PE_Hash PROC USES EBX hPE:DWORD, dwHashType:DWORD, lpHashBytes:DWORD, lpdwHashSize:DWORD
    LOCAL hProv:DWORD
    LOCAL hHash:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwBytesToRead:DWORD
    
    include advapi32.inc
    includelib advapi32.lib
    
    .CONST
    CRYPT_VERIFYCONTEXT EQU 0F0000000h
    PROV_RSA_AES        EQU 24
    HP_HASHVAL          EQU 2h
    HP_HASHSIZE         EQU 4h
    ALG_CLASS_HASH      EQU (4 SHL 13)
    ALG_TYPE_ANY        EQU 0
    ALG_SID_MD5         EQU 3
    ALG_SID_SHA1        EQU 4
    ALG_SID_SHA_256     EQU 12
    CALG_MD5            EQU (ALG_CLASS_HASH OR ALG_TYPE_ANY OR ALG_SID_MD5)
    CALG_SHA            EQU (ALG_CLASS_HASH OR ALG_TYPE_ANY OR ALG_SID_SHA)
    CALG_SHA1           EQU (ALG_CLASS_HASH OR ALG_TYPE_ANY OR ALG_SID_SHA1)
    CALG_SHA_256        EQU (ALG_CLASS_HASH OR ALG_TYPE_ANY OR ALG_SID_SHA_256)  
    MD5LEN              EQU 16 ; requires buffer of 32 chars long
    SHA1LEN             EQU 20 ; requires buffer of 40 chars long
    SHA256LEN           EQU 32 ; requires buffer of 64 chars long
    
    .CODE
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpHashBytes == 0 && lpdwHashSize == 0
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    mov eax, [ebx].PEINFO.PEFilesize
    mov dwBytesToRead, eax
    
    Invoke CryptAcquireContextA, Addr hProv, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
    .IF eax == 0
        ret
    .ENDIF
    
    ; Create hash
    mov eax, dwHashType
    .IF eax == 0 ; MD5
        Invoke CryptCreateHash, hProv, CALG_MD5, 0, 0, Addr hHash
    .ELSEIF eax == 1 ; SHA1
        Invoke CryptCreateHash, hProv, CALG_SHA1, 0, 0, Addr hHash
    .ELSEIF eax == 2 ; SHA256
        Invoke CryptCreateHash, hProv, CALG_SHA_256, 0, 0, Addr hHash
    .ELSE
        xor eax, eax
        ret
    .ENDIF
    .IF eax == 0
        ret
    .ENDIF
    
    ; Hash PE file mapped into memory
    Invoke CryptHashData, hHash, PEMemMapPtr, dwBytesToRead, 0
    .IF eax == 0
        ret
    .ENDIF
    
    ; Repurpose dwBytesToRead variable
    mov eax, dwHashType
    .IF eax == 0 ; MD5
        mov dwBytesToRead, MD5LEN
    .ELSEIF eax == 1 ; SHA1
        mov dwBytesToRead, SHA1LEN
    .ELSEIF eax == 2 ; SHA256
        mov dwBytesToRead, SHA256LEN
    .ELSE
        xor eax, eax
        ret
    .ENDIF
    
    ; Return hash bytes and/or hash size
    .IF lpHashBytes != 0
        Invoke CryptGetHashParam, hHash, HP_HASHVAL, lpHashBytes, Addr dwBytesToRead, 0
        .IF eax == 0
            ret
        .ENDIF
    .ENDIF
    .IF lpdwHashSize != 0
        Invoke CryptGetHashParam, hHash, HP_HASHSIZE, lpdwHashSize, Addr dwBytesToRead, 0
        .IF eax == 0
            ret
        .ENDIF
    .ENDIF
    
    Invoke CryptDestroyHash, hHash
    Invoke CryptReleaseContext, hProv, 0
    
    mov eax, TRUE
    ret
PE_Hash ENDP



PE_LIBEND

