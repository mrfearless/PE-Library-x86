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
; PE_SectionHeaderByType - Get section specified by dwSectionType
; Returns: pointer to section IMAGE_SECTION_HEADER or NULL
;------------------------------------------------------------------------------
PE_SectionHeaderByType PROC USES EBX hPE:DWORD, dwSectionType:DWORD
    LOCAL pHeaderSections:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nSection:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF    
    
    .IF dwSectionType > SEC_LAST
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_HeaderSections, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pHeaderSections, eax
    mov pCurrentSection, eax
    
    Invoke PE_SectionHeaderCount, hPE
    mov ebx, pCurrentSection
    mov nTotalSections, eax
    mov nSection, 0
    mov eax, 0
    .WHILE eax < nTotalSections
        .IF [ebx].IMAGE_SECTION_HEADER.Name1 != 0
            lea ebx, [ebx].IMAGE_SECTION_HEADER.Name1
            mov ebx, [ebx]
            mov eax, dwSectionType
            .IF eax == SEC_BSS
                .IF ebx == 'ssb.' ; .bss
                    mov eax, pCurrentSection
                    ret
                .ENDIF
            .ELSEIF eax == SEC_CORMETA
                .IF ebx == 'roc.' ; .cormeta
                    mov eax, pCurrentSection
                    ret
                .ENDIF  
            .ELSEIF eax == SEC_DATA
                .IF ebx == 'tad.' ; .data
                    mov eax, pCurrentSection
                    ret
                .ENDIF
            .ELSEIF eax == SEC_DEBUG
                .IF ebx == 'bed.' ; .debug
                    mov eax, pCurrentSection
                    ret
                .ENDIF                  
            .ELSEIF eax == SEC_DRECTVE
                .IF ebx == 'erd.' ; .drectve
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_EDATA
                .IF ebx == 'ade.' ; .edata
                    mov eax, pCurrentSection
                    ret
                .ENDIF            
            .ELSEIF eax == SEC_IDATA
                .IF ebx == 'adi.' ; .idata
                    mov eax, pCurrentSection
                    ret
                .ENDIF            
            .ELSEIF eax == SEC_IDLSYM
                .IF ebx == 'ldi.' ; .idlsym
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_PDATA
                .IF ebx == 'adp.' ; .pdata
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_RDATA
                .IF ebx == 'adr.' ; .rdata
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_RELOC
                .IF ebx == 'ler.' ; .reloc
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_RSRC
                .IF ebx == 'rsr.' ; .rsrc
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_SBSS
                .IF ebx == 'sbs.' ; .sbss
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_SDATA
                .IF ebx == 'ads.' ; .sdata
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_SRDATA
                .IF ebx == 'drs.' ; .srdata
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_SXDATA
                .IF ebx == 'dxs.' ; .sxdata
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_TEXT
                .IF ebx == 'xet.' ; .text
                    mov eax, pCurrentSection
                    ret
                .ENDIF            
            .ELSEIF eax == SEC_TLS
                .IF ebx == 'slt.' ; .tls
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_VSDATA
                .IF ebx == 'dsv.' ; .vsdata
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ELSEIF eax == SEC_XDATA
                .IF ebx == 'adx.' ; .xdata
                    mov eax, pCurrentSection
                    ret
                .ENDIF              
            .ENDIF
        .ENDIF
        
        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nSection
        mov eax, nSection
    .ENDW

    xor eax, eax
    ret
PE_SectionHeaderByType ENDP


PE_LIBEND

