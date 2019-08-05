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
include \masm32\macros\macros.asm

include windows.inc
include user32.inc
include kernel32.inc

includelib user32.lib
includelib kernel32.lib

include PE.inc


EXTERNDEF PEDwordToAscii        :PROTO :DWORD,:DWORD


.CODE


PE_ALIGN
;------------------------------------------------------------------------------
; PE_RichSignatureProduct - 
;------------------------------------------------------------------------------
PE_RichSignatureProduct PROC USES EBX ECX hPE:DWORD, dwCompIDIndex:DWORD, lpszProduct:DWORD
    LOCAL pHeaderRich:DWORD
    LOCAL pCompID:DWORD
    LOCAL nCompIDTotal:DWORD
    LOCAL RichXorKey:DWORD
    LOCAL dwCompID:DWORD
    LOCAL dwProdID:DWORD
    LOCAL dwBuild:DWORD
    LOCAL dwUses:DWORD
    LOCAL szBuild[16]:BYTE
    
    .IF lpszProduct == NULL
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_HeaderRich, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pHeaderRich, eax
    
    Invoke PE_RichSignatureCompIDs, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov nCompIDTotal, eax
    
    .IF dwCompIDIndex >= eax
        xor eax, eax
        ret
    .ENDIF
    
    ; Get xor key
    mov eax, nCompIDTotal
    mov ebx, 8
    mul ebx
    add eax, 4+12+4 ; DanS, padding and Rich
    add eax, pHeaderRich
    mov ebx, eax
    mov eax, [ebx]
    mov RichXorKey, eax
    
    ; Get pointer to CompID we are interested in
    mov eax, dwCompIDIndex
    mov ebx, 8
    mul ebx
    add eax, 4+12 ; DanS, padding
    add eax, pHeaderRich
    mov pCompID, eax
    
    ; Get CompID
    mov ebx, pCompID
    mov eax, [ebx] ; CompID encrypted
    mov ebx, RichXorKey
    xor eax, ebx ; decode
    mov dwCompID, eax
    
    ; Get Uses
    mov ebx, pCompID
    add ebx, 4
    mov eax, [ebx] ; Uses encrypted
    mov ebx, RichXorKey
    xor eax, ebx ; decode
    mov dwUses, eax
    
    ; Get ProdID and Build from CompID
    mov eax, dwCompID
    shr eax, 16
    mov dwProdID, eax
    mov eax, dwCompID
    and eax, 0FFFFh
    mov dwBuild, eax
    
    mov eax, dwProdID
    .IF eax == 0
        Invoke lstrcpy, lpszProduct, CTEXT("Unknown")
        ret
    .ELSEIF eax == 1 ; total count of imported DLL functions referenced; build number is always zero - only counts kernel32, user32 (+gdi32?)
        Invoke lstrcpy, lpszProduct, CTEXT("Imported Core DLL functions: ")
        Invoke PEDwordToAscii, dwUses, Addr szBuild
        Invoke lstrcat, lpszProduct, Addr szBuild
        
    ;------------------------------------------------------------------------
    ; MASM
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_MASM613
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 6.13")
    .ELSEIF eax == ID_MASM614
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 6.14")
    .ELSEIF eax == ID_MASM615
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 6.15")
    .ELSEIF eax == ID_MASM620
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 6.20")
    .ELSEIF eax == ID_MASM700
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 7.00")
    .ELSEIF eax == ID_MASM710
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 7.10")
    .ELSEIF eax == ID_MASM710P
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 7.10")
    .ELSEIF eax == ID_MASM800
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 8.00")
    .ELSEIF eax == ID_MASM900
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 9.00")
    .ELSEIF eax == ID_MASM1000
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 10.00")
    .ELSEIF eax == ID_MASM1010
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 10.10")
    .ELSEIF eax == ID_MASM1100
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 11.00")
    .ELSEIF eax == ID_MASM1200
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 12.00")
    .ELSEIF eax == ID_MASM1210
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 12.10")
    .ELSEIF eax == ID_MASM1400
        Invoke lstrcpy, lpszProduct, CTEXT("Masm 14.00")
    ;------------------------------------------------------------------------
    ; LINKERS
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_LINKER510
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 5.10")
    .ELSEIF eax == ID_LINKER511
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 5.11")
    .ELSEIF eax == ID_LINKER512
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 5.12")
    .ELSEIF eax == ID_LINKER600
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 6.00")
    .ELSEIF eax == ID_LINKER601
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 6.01")
    .ELSEIF eax == ID_LINKER610
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 6.10")
    .ELSEIF eax == ID_LINKER620
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 6.20")
    .ELSEIF eax == ID_LINKER621
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 6.21")
    .ELSEIF eax == ID_LINKER622
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 6.22")
    .ELSEIF eax == ID_LINKER624
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 6.24")
    .ELSEIF eax == ID_LINKER700
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 7.00")
    .ELSEIF eax == ID_LINKER710P
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 7.10")
    .ELSEIF eax == ID_LINKER710
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 7.10")
    .ELSEIF eax == ID_LINKER800
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 8.00")
    .ELSEIF eax == ID_LINKER900
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 9.00")
    .ELSEIF eax == ID_LINKER1000
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 10.00")
    .ELSEIF eax == ID_LINKER1010
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 10.10")
    .ELSEIF eax == ID_LINKER1100
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 11.00")
    .ELSEIF eax == ID_LINKER1200
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 12.00")
    .ELSEIF eax == ID_LINKER1210
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 12.10")
    .ELSEIF eax == ID_LINKER1400
        Invoke lstrcpy, lpszProduct, CTEXT("Linker 14.00")
    ;------------------------------------------------------------------------
    ; RESOURCE
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_CVTRES500
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 5.00")
    .ELSEIF eax == ID_CVTRES501
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 5.01")
    .ELSEIF eax == ID_CVTRES700
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 7.00")
    .ELSEIF eax == ID_CVTRES710P
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 7.10")
    .ELSEIF eax == ID_CVTRES710
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 7.10")
    .ELSEIF eax == ID_CVTRES800
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 8.00")
    .ELSEIF eax == ID_CVTRES900
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 9.00")
    .ELSEIF eax == ID_CVTRES1000
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 10.00")
    .ELSEIF eax == ID_CVTRES1010
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 10.10")
    .ELSEIF eax == ID_CVTRES1100
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 11.00")
    .ELSEIF eax == ID_CVTRES1200
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 12.00")
    .ELSEIF eax == ID_CVTRES1210
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 12.10")
    .ELSEIF eax == ID_CVTRES1400
        Invoke lstrcpy, lpszProduct, CTEXT("Resource 14.00")
    ;------------------------------------------------------------------------
    ; IMPORT
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_IMPLIB622 || eax == ID_IMPLIB624 || eax == ID_IMPLIB700 || eax == ID_IMPLIB710P || eax == ID_IMPLIB710 || eax == ID_IMPLIB800 || eax == ID_IMPLIB900 || eax == ID_IMPLIB1000 || eax == ID_IMPLIB1010 || eax == ID_IMPLIB1100 || eax == ID_IMPLIB1200 || eax == ID_IMPLIB1210 || eax == ID_IMPLIB1400
        Invoke lstrcpy, lpszProduct, CTEXT("Import Library")
        ret
    ;------------------------------------------------------------------------
    ; EXPORT
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_EXPORT622 || eax == ID_EXPORT624 || eax == ID_EXPORT700 || eax == ID_EXPORT710P || eax == ID_EXPORT710 || eax == ID_EXPORT800 || eax == ID_EXPORT900 || eax == ID_EXPORT1000 || eax == ID_EXPORT1010 || eax == ID_EXPORT1100 || eax == ID_EXPORT1200 || eax == ID_EXPORT1210 || eax == ID_EXPORT1400
        Invoke lstrcpy, lpszProduct, CTEXT("Export")
        ret
    ;------------------------------------------------------------------------
    ; ALIAS
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_ALIASOBJ60
        Invoke lstrcpy, lpszProduct, CTEXT("Object 6.00")
    .ELSEIF eax == ID_ALIASOBJ70
        Invoke lstrcpy, lpszProduct, CTEXT("Object 7.00")
    .ELSEIF eax == ID_ALIASOBJ710
        Invoke lstrcpy, lpszProduct, CTEXT("Object 7.10")
    .ELSEIF eax == ID_ALIASOBJ710P
        Invoke lstrcpy, lpszProduct, CTEXT("Object 7.10")
    .ELSEIF eax == ID_ALIASOBJ800
        Invoke lstrcpy, lpszProduct, CTEXT("Object 8.00")
    .ELSEIF eax == ID_ALIASOBJ900
        Invoke lstrcpy, lpszProduct, CTEXT("Object 9.00")
    .ELSEIF eax == ID_ALIASOBJ1000
        Invoke lstrcpy, lpszProduct, CTEXT("Object 10.00")
    .ELSEIF eax == ID_ALIASOBJ1010
        Invoke lstrcpy, lpszProduct, CTEXT("Object 10.10")
    .ELSEIF eax == ID_ALIASOBJ1100
        Invoke lstrcpy, lpszProduct, CTEXT("Object 11.00")
    .ELSEIF eax == ID_ALIASOBJ1200
        Invoke lstrcpy, lpszProduct, CTEXT("Object 12.00")
    .ELSEIF eax == ID_ALIASOBJ1210
        Invoke lstrcpy, lpszProduct, CTEXT("Object 12.10")
    .ELSEIF eax == ID_ALIASOBJ1400
        Invoke lstrcpy, lpszProduct, CTEXT("Object 14.00")
    ;------------------------------------------------------------------------
    ; C++
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_CPP_VS98                 ; VS98 6.0
        Invoke lstrcpy, lpszProduct, CTEXT("VS98 C++ 6.0")
    .ELSEIF eax == ID_CPP_VCPP6SP5             ; MSVC++ 6.0 SP5
        Invoke lstrcpy, lpszProduct, CTEXT("VC++ 6.0")
    .ELSEIF eax == ID_CPP_VS2002               ; MSVS2002 (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2002 C++ ")
    .ELSEIF eax == ID_CPP_VS2003_1310P         ; MSVS2003 1310p (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2003 C++ 13.10")
    .ELSEIF eax == ID_CPP_VS2003_1310P_STD     ; MSVS2003 1310p Std (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2003 C++ 13.10")
    .ELSEIF eax == ID_CPP_VS2003_1310          ; MSVS2003 1310 (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2003 C++ 13.10")
    .ELSEIF eax == ID_CPP_VS2003_1310_STD      ; MSVS2003 1310 Std (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2003 C++ 13.10")
    .ELSEIF eax == ID_CPP_VS2005_1400          ; MSVS2005 1400
        Invoke lstrcpy, lpszProduct, CTEXT("VS2005 C++ 14.00")
    .ELSEIF eax == ID_CPP_VS2005_1400_STD      ; MSVS2005 1400 Std
        Invoke lstrcpy, lpszProduct, CTEXT("VS2005 C++ 14.00")
    .ELSEIF eax == ID_CPP_VS2008_1500          ; MSVS2008 1500
        Invoke lstrcpy, lpszProduct, CTEXT("VS2008 C++ 15.00")
    .ELSEIF eax == ID_CPP_VS2008_1500_STD      ; MSVS2008 1500 Std
        Invoke lstrcpy, lpszProduct, CTEXT("VS2008 C++ 15.00")
    .ELSEIF eax == ID_CPP_VS2010_1600          ; MSVS2010 1600
        Invoke lstrcpy, lpszProduct, CTEXT("VS2010 C++ 16.00")
    .ELSEIF eax == ID_CPP_VS2010_1610          ; MSVS2010 1610
        Invoke lstrcpy, lpszProduct, CTEXT("VS2010 C++ 16.10")
    .ELSEIF eax == ID_CPP_VS2012_1700          ; MSVS2012 1700
        Invoke lstrcpy, lpszProduct, CTEXT("VS2012 C++ 17.00")
    .ELSEIF eax == ID_CPP_VS2013_1800          ; MSVS2013 1800
        Invoke lstrcpy, lpszProduct, CTEXT("VS2013 C++ 18.00")
    .ELSEIF eax == ID_CPP_VS2013_1810          ; MSVS2013 1810
        Invoke lstrcpy, lpszProduct, CTEXT("VS2013 C++ 18.10")
    .ELSEIF eax == ID_CPP_VS2015_1900          ; MSVS2015 1900 (Community)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2015 C++ 19.00")
    ;------------------------------------------------------------------------
    ; C
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_C_VS98                   ; MSVS98 6.0
        Invoke lstrcpy, lpszProduct, CTEXT("VS98 C 6.0")
    .ELSEIF eax == ID_C_VCPP6SP5               ; MSVC++ 6.0 SP5
        Invoke lstrcpy, lpszProduct, CTEXT("VC++ C 6.0")
    .ELSEIF eax == ID_C_VS2002                 ; MSVS2002 (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2002 C ")
    .ELSEIF eax == ID_C_VS2003_1310P           ; MSVS2003 1310p (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2003 C 13.10")
    .ELSEIF eax == ID_C_VS2003_1310P_STD       ; MSVS2003 1310p Std (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2003 C 13.10")
    .ELSEIF eax == ID_C_VS2003_1310            ; MSVS2003 1310 (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2003 C 13.10")
    .ELSEIF eax == ID_C_VS2003_1310_STD        ; MSVS2003 1310 Std (.NET)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2003 C 13.10")
    .ELSEIF eax == ID_C_VS2005_1400            ; MSVS2005 1400
        Invoke lstrcpy, lpszProduct, CTEXT("VS2005 C 14.00")
    .ELSEIF eax == ID_C_VS2005_1400_STD        ; MSVS2005 1400 Std
        Invoke lstrcpy, lpszProduct, CTEXT("VS2005 C 14.00")
    .ELSEIF eax == ID_C_VS2008_1500            ; MSVS2008 1500
        Invoke lstrcpy, lpszProduct, CTEXT("VS2008 C 15.00")
    .ELSEIF eax == ID_C_VS2008_1500_STD        ; MSVS2008 1500 Std
        Invoke lstrcpy, lpszProduct, CTEXT("VS2008 C 15.00")
    .ELSEIF eax == ID_C_VS2010_1600            ; MSVS2010 1600
        Invoke lstrcpy, lpszProduct, CTEXT("VS2010 C 16.00")
    .ELSEIF eax == ID_C_VS2010_1610            ; MSVS2010 1610
        Invoke lstrcpy, lpszProduct, CTEXT("VS2010 C 16.00")
    .ELSEIF eax == ID_C_VS2012_1700            ; MSVS2012 1700
        Invoke lstrcpy, lpszProduct, CTEXT("VS2012 C 17.00")
    .ELSEIF eax == ID_C_VS2013_1800            ; MSVS2013 1800
        Invoke lstrcpy, lpszProduct, CTEXT("VS2013 C 18.00")
    .ELSEIF eax == ID_C_VS2013_1810            ; MSVS2013 1810
        Invoke lstrcpy, lpszProduct, CTEXT("VS2013 C 18.10")
    .ELSEIF eax == ID_C_VS2015_1900            ; MSVS2015 1900 (Community)
        Invoke lstrcpy, lpszProduct, CTEXT("VS2015 C 19.00")
    ;------------------------------------------------------------------------
    ; Link Time Code Generation (LTCG) for C/CPP/MSIL (Microsoft Intermediate Language):
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_LTCG_C____13
    .ELSEIF eax == ID_LTCG_CPP__13
    .ELSEIF eax == ID_LTCG_C____1310P
    .ELSEIF eax == ID_LTCG_CPP__1310P
    .ELSEIF eax == ID_LTCG_C____1310
    .ELSEIF eax == ID_LTCG_CPP__1310
    .ELSEIF eax == ID_LTCG_C____1400
    .ELSEIF eax == ID_LTCG_CPP__1400
    .ELSEIF eax == ID_LTCG_MSIL_1400
    .ELSEIF eax == ID_LTCG_C____1500
    .ELSEIF eax == ID_LTCG_CPP__1500
    .ELSEIF eax == ID_LTCG_MSIL_1500
    .ELSEIF eax == ID_LTCG_C____1600PHX
    .ELSEIF eax == ID_LTCG_CPP__1600PHX
    .ELSEIF eax == ID_LTCG_MSIL_1600PHX
    .ELSEIF eax == ID_LTCG_C____1600
    .ELSEIF eax == ID_LTCG_CPP__1600
    .ELSEIF eax == ID_LTCG_MSIL_1600
    .ELSEIF eax == ID_LTCG_C____1610
    .ELSEIF eax == ID_LTCG_CPP__1610
    .ELSEIF eax == ID_LTCG_MSIL_1610
    .ELSEIF eax == ID_LTCG_C____1700
    .ELSEIF eax == ID_LTCG_CPP__1700
    .ELSEIF eax == ID_LTCG_MSIL_1700
    .ELSEIF eax == ID_LTCG_C____1800
    .ELSEIF eax == ID_LTCG_CPP__1800
    .ELSEIF eax == ID_LTCG_MSIL_1800
    .ELSEIF eax == ID_LTCG_C____1810
    .ELSEIF eax == ID_LTCG_CPP__1810
    .ELSEIF eax == ID_LTCG_MSIL_1810
    .ELSEIF eax == ID_LTCG_C____1900
    .ELSEIF eax == ID_LTCG_CPP__1900
    .ELSEIF eax == ID_LTCG_MSIL_1900
    ;------------------------------------------------------------------------
    ; Profile Guided Optimizations (POGO/PGO) - POGO_I = /LTCG:PGINSTRUMENT /LTCG:PGI - POGO_O = /LTCG:PGOPTIMIZE /LTCG:PGO
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_POGO_I_C___13
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 13.00")
    .ELSEIF eax == ID_POGO_I_CPP_13
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 13.00")
    .ELSEIF eax == ID_POGO_O_C___13
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 13.00")
    .ELSEIF eax == ID_POGO_O_CPP_13
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 13.00")
    .ELSEIF eax == ID_POGO_I_C__1310P
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 13.10")
    .ELSEIF eax == ID_POGO_I_CP_1310P
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 13.00")
    .ELSEIF eax == ID_POGO_O_C__1310P
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 13.10")
    .ELSEIF eax == ID_POGO_O_CP_1310P
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 13.10")
    .ELSEIF eax == ID_POGO_I_C___1310
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 13.10")
    .ELSEIF eax == ID_POGO_I_CPP_1310
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 13.00")
    .ELSEIF eax == ID_POGO_O_C___1310
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 13.10")
    .ELSEIF eax == ID_POGO_O_CPP_1310
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 13.10")
    .ELSEIF eax == ID_POGO_I_C___1400
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 14.00")
    .ELSEIF eax == ID_POGO_I_CPP_1400
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 14.00")
    .ELSEIF eax == ID_POGO_O_C___1400
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 14.00")
    .ELSEIF eax == ID_POGO_O_CPP_1400
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 14.00")
    .ELSEIF eax == ID_POGO_I_C___1500
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 15.00")
    .ELSEIF eax == ID_POGO_I_CPP_1500
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 15.00")
    .ELSEIF eax == ID_POGO_O_C___1500
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 15.00")
    .ELSEIF eax == ID_POGO_O_CPP_1500
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 15.00")
    .ELSEIF eax == ID_POGO_I_C___1600PHX
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C (Phoenix) 16.00")
    .ELSEIF eax == ID_POGO_I_CPP_1600PHX
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ (Phoenix) 16.00")
    .ELSEIF eax == ID_POGO_O_C___1600PHX
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C (Phoenix) 16.00")
    .ELSEIF eax == ID_POGO_O_CPP_1600PHX
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ (Phoenix) 16.00")
    .ELSEIF eax == ID_POGO_I_C___1600
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 16.00")
    .ELSEIF eax == ID_POGO_I_CPP_1600
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 16.00")
    .ELSEIF eax == ID_POGO_O_C___1600
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 16.00")
    .ELSEIF eax == ID_POGO_O_CPP_1600
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 16.00")
    .ELSEIF eax == ID_POGO_I_C___1610
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 16.10")
    .ELSEIF eax == ID_POGO_I_CPP_1610
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 16.10")
    .ELSEIF eax == ID_POGO_O_C___1610
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 16.10")
    .ELSEIF eax == ID_POGO_O_CPP_1610
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 16.10")
    .ELSEIF eax == ID_POGO_I_C___1700
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 17.00")
    .ELSEIF eax == ID_POGO_I_CPP_1700
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 17.00")
    .ELSEIF eax == ID_POGO_O_C___1700
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 17.00")
    .ELSEIF eax == ID_POGO_O_CPP_1700
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 17.00")
    .ELSEIF eax == ID_POGO_I_C___1800
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 18.00")
    .ELSEIF eax == ID_POGO_I_CPP_1800
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 18.00")
    .ELSEIF eax == ID_POGO_O_C___1800
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 18.00")
    .ELSEIF eax == ID_POGO_O_CPP_1800
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 18.00")
    .ELSEIF eax == ID_POGO_I_C___1810
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 18.10")
    .ELSEIF eax == ID_POGO_I_CPP_1810
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 18.10")
    .ELSEIF eax == ID_POGO_O_C___1810
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 18.10")
    .ELSEIF eax == ID_POGO_O_CPP_1810
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 18.10")
    .ELSEIF eax == ID_POGO_I_C___1900
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C 19.00")
    .ELSEIF eax == ID_POGO_I_CPP_1900
        Invoke lstrcpy, lpszProduct, CTEXT("PGI C++ 19.00")
    .ELSEIF eax == ID_POGO_O_C___1900
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C 19.00")
    .ELSEIF eax == ID_POGO_O_CPP_1900
        Invoke lstrcpy, lpszProduct, CTEXT("PGO C++ 19.00")
    ;------------------------------------------------------------------------
    ; Microsoft CIL to Native Converter (CVTCIL)
    ;------------------------------------------------------------------------
    .ELSEIF eax == ID_CVTCIL_C___1400
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C 14.00")
    .ELSEIF eax == ID_CVTCIL_CPP_1400
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ 14.00")
    .ELSEIF eax == ID_CVTCIL_C___1500
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C 14.00")
    .ELSEIF eax == ID_CVTCIL_CPP_1500
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ 15.00")
    .ELSEIF eax == ID_CVTCIL_C___1600PHX
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C (Phoenix) 16.00")
    .ELSEIF eax == ID_CVTCIL_CPP_1600PHX
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ (Phoenix) 16.00")
    .ELSEIF eax == ID_CVTCIL_C___1600
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C 16.00")
    .ELSEIF eax == ID_CVTCIL_CPP_1600
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ 16.00")
    .ELSEIF eax == ID_CVTCIL_C___1610
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C 16.10")
    .ELSEIF eax == ID_CVTCIL_CPP_1610
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ 16.10")
    .ELSEIF eax == ID_CVTCIL_C___1700
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C 17.00")
    .ELSEIF eax == ID_CVTCIL_CPP_1700
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ 17.00")
    .ELSEIF eax == ID_CVTCIL_C___1800
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C 18.00")
    .ELSEIF eax == ID_CVTCIL_CPP_1800
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ 18.00")
    .ELSEIF eax == ID_CVTCIL_C___1810
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C 18.10")
    .ELSEIF eax == ID_CVTCIL_CPP_1810
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ 18.10")
    .ELSEIF eax == ID_CVTCIL_C___1900
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C 19.00")
    .ELSEIF eax == ID_CVTCIL_CPP_1900
        Invoke lstrcpy, lpszProduct, CTEXT("CVTCIL C++ 19.00")
        
    .ENDIF

    .IF dwBuild != 0
        Invoke PEDwordToAscii, dwBuild, Addr szBuild
        Invoke lstrcat, lpszProduct, CTEXT(".")
        Invoke lstrcat, lpszProduct, Addr szBuild
    .ENDIF
    
    mov eax, TRUE
    ret
PE_RichSignatureProduct ENDP


PE_LIBEND

