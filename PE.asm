;==============================================================================
;
; PE LIBRARY
;
; Copyright (c) 2019 by fearless
;
; All Rights Reserved
;
; http://www.LetTheLight.in
;
; http://github.com/mrfearless
;
;
; This software is provided 'as-is', without any express or implied warranty.
; In no event will the author be held liable for any damages arising from the
; use of this software.
;
; Permission is granted to anyone to use this software for any non-commercial
; program. If you use the library in an application, an acknowledgement in the
; application or documentation is appreciated but not required.
;
; You are allowed to make modifications to the source code, but you must leave
; the original copyright notices intact and not misrepresent the origin of the
; software. It is not allowed to claim you wrote the original software.
; Modified files must have a clear notice that the files are modified, and not
; in the original state. This includes the name of the person(s) who modified
; the code.
;
; If you want to distribute or redistribute any portion of this package, you
; will need to include the full package in it's original state, including this
; license and all the copyrights.
;
; While distributing this package (in it's original state) is allowed, it is
; not allowed to charge anything for this. You may not sell or include the
; package in any commercial package without having permission of the author.
; Neither is it allowed to redistribute any of the package's components with
; commercial applications.
;
;==============================================================================
.686
.MMX
.XMM
.model flat,stdcall
option casemap:none
include \masm32\macros\macros.asm

DEBUG32 EQU 1
IFDEF DEBUG32
    PRESERVEXMMREGS equ 1
    includelib M:\Masm32\lib\Debug32.lib
    DBG32LIB equ 1
    DEBUGEXE textequ <'M:\Masm32\DbgWin.exe'>
    include M:\Masm32\include\debug32.inc
ENDIF

include windows.inc

include user32.inc
includelib user32.lib

include kernel32.inc
includelib kernel32.lib

include PE.inc

;-------------------------------------------------------------------------
; Prototypes for internal use
;-------------------------------------------------------------------------
PESignature             PROTO :DWORD
PEJustFname             PROTO :DWORD, :DWORD
PE_SetError             PROTO :DWORD

PUBLIC PELIB_ErrorNo

;-------------------------------------------------------------------------
; Structures for internal use
;-------------------------------------------------------------------------

IFNDEF PEINFO
PEINFO                      STRUCT
    PEOpenMode              DD 0
    PEFilename              DB MAX_PATH DUP (0)
    PEFilesize              DD 0
    PEVersion               DD 0
    PE64                    DD 0
    PEDLL                   DD 0
    PEDOSHeader             DD 0
    PENTHeader              DD 0
    PEFileHeader            DD 0
    PEOptionalHeader        DD 0
    PESectionTable          DD 0
    PEMachine               DD 0
    PESectionCount          DD 0
    PEOptionalHeaderSize    DD 0
    PECharacteristics       DD 0
    PEAddressOfEntryPoint   DD 0
    PEImageBase             DD 0
    PE64ImageBase           DQ 0
    PESubsystem             DD 0
    PEDllCharacteristics    DD 0
    PEDataDirectories       DD 0
    PEExportCount           DD 0
    PEExportDirPtr          DD 0
    PEExportAddressTable    DD 0
    PEExportNamePointerTable DD 0
    PEExportOrdinalTable    DD 0
    PEExportNameTable       DD 0
    PEImportCount           DD 0
    PEImportDirectoryTable  DD 0
    PEImportLookupTable     DD 0
    PEImportNameTable       DD 0
    PEImportAddressTable    DD 0
    PEResourceDirectoryTable DD 0
    PEResourceDirectoryEntries DD 0
    PEResourceDirectoryString DD 0
    PEResourceDataEntry     DD 0
    PEDebugDirectory        DD 0
    PEBaseRelocationBlock   DD 0
    PEMemMapPtr             DD 0
    PEMemMapHandle          DD 0
    PEFileHandle            DD 0
PEINFO                      ENDS
ENDIF

.CONST



.DATA
PELIB_ErrorNo           DD 0 ; Global to store error no


.CODE
PE_ALIGN
;------------------------------------------------------------------------------
; PE_OpenFile - Opens a PE file (exe/dll/ocx/cpl etc)
; Returns: in eax hPE on success or NULL otherwise. 
; If NULL then use PE_GetError to get further information
; Note: Calls PE_Analyze to process the PE file.
;------------------------------------------------------------------------------
PE_OpenFile PROC USES EBX lpszPEFilename:DWORD
    LOCAL hPE:DWORD
    LOCAL hPEFile:DWORD
    LOCAL PEMemMapHandle:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL PEFilesize:DWORD
    LOCAL PEVersion:DWORD
    
    .IF lpszPEFilename == NULL
        Invoke PE_SetError, PE_ERROR_OPEN_FILE
        mov eax, NULL
        ret
    .ENDIF
    
    ;Invoke CreateFile, lpszPEFilename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    Invoke CreateFile, lpszPEFilename, GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    .IF eax == INVALID_HANDLE_VALUE
        Invoke PE_SetError, PE_ERROR_OPEN_FILE
        mov eax, NULL
        ret
    .ENDIF
    mov hPEFile, eax

    Invoke GetFileSize, hPEFile, NULL
    .IF eax < 268d ; https://www.bigmessowires.com/2015/10/08/a-handmade-executable-file/
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, PE_ERROR_OPEN_SIZE_LOW
        mov eax, NULL
        ret
    .ELSEIF eax > 1FFFFFFFh ; 536,870,911 536MB+
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, PE_ERROR_OPEN_SIZE_HIGH
        mov eax, NULL
        ret    
    .ENDIF
    mov PEFilesize, eax

    ;---------------------------------------------------
    ; File Mapping: Create file mapping for main .exe .dll
    ;---------------------------------------------------
    ;Invoke CreateFileMapping, hPEFile, NULL, PAGE_READWRITE, 0, 0, NULL ; Create memory mapped file
    Invoke CreateFileMapping, hPEFile, NULL, PAGE_READONLY, 0, 0, NULL ; Create memory mapped file
    .IF eax == NULL
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, PE_ERROR_OPEN_MAP
        mov eax, NULL
        ret
    .ENDIF
    mov PEMemMapHandle, eax

    ;Invoke MapViewOfFileEx, PEMemMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0, NULL
    Invoke MapViewOfFileEx, PEMemMapHandle, FILE_MAP_READ, 0, 0, 0, NULL
    .IF eax == NULL
        Invoke CloseHandle, PEMemMapHandle
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, PE_ERROR_OPEN_VIEW
        mov eax, NULL
        ret
    .ENDIF
    mov PEMemMapPtr, eax

    Invoke PESignature, PEMemMapPtr
    ;mov PEVersion, eax
    .IF eax == PE_INVALID ; not a valid PE (exe, dll etc) file
        Invoke UnmapViewOfFile, PEMemMapPtr
        Invoke CloseHandle, PEMemMapHandle
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, PE_ERROR_OPEN_INVALID
        mov eax, NULL
        ret

    .ELSE ; SigReturn == PE_ARCH_32 || SigReturn == PE_ARCH_64
        Invoke PE_Analyze, PEMemMapPtr
        mov hPE, eax
        .IF hPE == NULL
            Invoke UnmapViewOfFile, PEMemMapPtr
            Invoke CloseHandle, PEMemMapHandle
            Invoke CloseHandle, hPEFile
            Invoke PE_SetError, PE_ERROR_OPEN_INVALID
            mov eax, NULL
            ret
        .ENDIF
        
        mov ebx, hPE
        mov eax, PEMemMapHandle
        mov [ebx].PEINFO.PEMemMapHandle, eax
        mov eax, hPEFile
        mov [ebx].PEINFO.PEFileHandle, eax
        mov eax, PEFilesize
        mov [ebx].PEINFO.PEFilesize, eax
        .IF lpszPEFilename != NULL
            lea eax, [ebx].PEINFO.PEFilename
            Invoke lstrcpyn, eax, lpszPEFilename, MAX_PATH
        .ENDIF        
        
    .ENDIF
    
    Invoke PE_SetError, PE_ERROR_SUCCESS
    
    ; save version for later use
    ;mov ebx, hPE
    ;mov eax, PEVersion
    ;mov [ebx].PEINFO.PEVersion, eax
    mov eax, hPE
    ret
PE_OpenFile ENDP


PE_ALIGN
;------------------------------------------------------------------------------
; PE_CloseFile - Close PE File
;------------------------------------------------------------------------------
PE_CloseFile PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF

    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    .IF eax != NULL
        Invoke UnmapViewOfFile, eax
    .ENDIF

    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapHandle
    .IF eax != NULL
        Invoke CloseHandle, eax
    .ENDIF

    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFileHandle
    .IF eax != NULL
        Invoke CloseHandle, eax
    .ENDIF

    mov eax, hPE
    .IF eax != NULL
        Invoke GlobalFree, eax
    .ENDIF

    xor eax, eax
    ret
PE_CloseFile ENDP


PE_ALIGN
;------------------------------------------------------------------------------
; PE_Analyze - Process memory mapped PE file 
; Returns: in eax hPE on success or NULL otherwise. 
; If NULL then use PE_GetError to get further information
; Can be used directly on memory region where PE is already loaded/mapped, if
; using directly then no need to 
; PE_Analyze is also called by PE_OpenFile.
; Use PE_Finish when finished with PE file if using PE_Analyze directly.
;------------------------------------------------------------------------------
PE_Analyze PROC USES EBX pPEInMemory:DWORD
    LOCAL hPE:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pNTHeader:DWORD
    LOCAL pFileHeader:DWORD
    LOCAL pOptionalHeader:DWORD
    LOCAL pDataDirectories:DWORD    
    LOCAL pSectionTable:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwMachine:DWORD
    LOCAL dwNumberOfSections:DWORD
    LOCAL dwSizeOfOptionalHeader:DWORD
    LOCAL dwCharacteristics:DWORD
    LOCAL dwAddressOfEntryPoint:DWORD
    LOCAL dwImageBase:DWORD
    LOCAL qwImageBase:QWORD
    LOCAL dwSubsystem:DWORD
    LOCAL dwDllCharacteristics:DWORD
    LOCAL dwNumberOfRvaAndSizes:DWORD
    LOCAL dwCurrentSection:DWORD
    LOCAL bPE64:DWORD
    
    .IF pPEInMemory == NULL
        Invoke PE_SetError, PE_ERROR_ANALYZE_NULL
        mov eax, NULL
        ret
    .ENDIF
    
    mov eax, pPEInMemory
    mov PEMemMapPtr, eax       
    
    ;--------------------------------------------------------------------------
    ; Alloc mem for our PE Handle (PEINFO)
    ;--------------------------------------------------------------------------
    Invoke GlobalAlloc, GMEM_FIXED or GMEM_ZEROINIT, SIZEOF PEINFO
    .IF eax == NULL
        Invoke PE_SetError, PE_ERROR_ANALYZE_ALLOC
        mov eax, NULL
        ret
    .ENDIF
    mov hPE, eax
    
    mov ebx, hPE
    mov eax, PEMemMapPtr
    mov [ebx].PEINFO.PEMemMapPtr, eax
    mov [ebx].PEINFO.PEDOSHeader, eax

    ; Process PE in memory
    mov eax, PEMemMapPtr
    mov ebx, eax ; ebx points to IMAGE_DOS_HEADER in memory
    .IF [ebx].IMAGE_DOS_HEADER.e_lfanew != 0
        ;----------------------------------------------------------------------
        ; Get headers: NT, File, Optional & other useful fields
        ;----------------------------------------------------------------------
        add eax, [ebx].IMAGE_DOS_HEADER.e_lfanew
        mov pNTHeader, eax
        mov ebx, eax ; ebx points to IMAGE_NT_HEADERS
        lea eax, [ebx].IMAGE_NT_HEADERS.FileHeader
        mov pFileHeader, eax
        lea eax, [ebx].IMAGE_NT_HEADERS.OptionalHeader
        mov pOptionalHeader, eax
        
        mov ebx, pFileHeader ; ebx points to IMAGE_FILE_HEADER
        movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.Machine
        mov dwMachine, eax
        movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.NumberOfSections
        mov dwNumberOfSections, eax
        movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.SizeOfOptionalHeader
        mov dwSizeOfOptionalHeader, eax
        movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.Characteristics
        mov dwCharacteristics, eax
                
        .IF dwSizeOfOptionalHeader == 0
            mov pOptionalHeader, 0
            mov pDataDirectories, 0
            mov dwNumberOfRvaAndSizes, 0
            mov dwImageBase, 0
            mov dword ptr qwImageBase, 0
            mov dword ptr qwImageBase+4, 0
            mov dwSubsystem, 0
            mov dwDllCharacteristics, 0
            mov bPE64, FALSE
        .ELSE
            ;------------------------------------------------------------------
            ; Get PE32/PE32+ magic number
            ;------------------------------------------------------------------
            mov ebx, pOptionalHeader; ebx points to IMAGE_OPTIONAL_HEADER
            movzx eax, word ptr [ebx]
            .IF eax == IMAGE_NT_OPTIONAL_HDR32_MAGIC ; PE32
                mov ebx, hPE
                mov [ebx].PEINFO.PE64, FALSE
                mov bPE64, FALSE
            .ELSEIF eax == IMAGE_NT_OPTIONAL_HDR64_MAGIC ; PE32+ (PE64)
                mov ebx, hPE
                mov [ebx].PEINFO.PE64, TRUE
                mov bPE64, TRUE
            .ELSE ; ROM or something else
                Invoke PE_SetError, PE_ERROR_ANALYZE_INVALID
                mov eax, NULL
                ret
            .ENDIF
            
            mov ebx, pOptionalHeader; ebx points to IMAGE_OPTIONAL_HEADER
            mov eax, [ebx].IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
            mov dwAddressOfEntryPoint, eax

            mov eax, dwSizeOfOptionalHeader
            .IF eax == 28 || eax == 24
                ;--------------------------------------------------------------
                ; Standard fields in IMAGE_OPTIONAL_HEADER
                ;--------------------------------------------------------------
                mov pDataDirectories, 0
                mov dwNumberOfRvaAndSizes, 0
                mov dwImageBase, 0
                mov dword ptr qwImageBase, 0
                mov dword ptr qwImageBase+4, 0
                mov dwSubsystem, 0
                mov dwDllCharacteristics, 0
            .ELSEIF eax == 68 || eax == 88 ; Windows specific fields in IMAGE_OPTIONAL_HEADER
                ;--------------------------------------------------------------
                ; Windows specific fields in IMAGE_OPTIONAL_HEADER
                ; Get ImageBase, Subsystem, DllCharacteristics
                ;--------------------------------------------------------------
                mov pDataDirectories, 0
                mov dwNumberOfRvaAndSizes, 0
                mov ebx, pOptionalHeader ; ebx points to IMAGE_OPTIONAL_HEADER
                .IF bPE64 == TRUE ; ebx points to IMAGE_OPTIONAL_HEADER64
                    mov eax, dword ptr [ebx].IMAGE_OPTIONAL_HEADER64.ImageBase
                    mov dword ptr qwImageBase, eax
                    mov eax, dword ptr [ebx+4].IMAGE_OPTIONAL_HEADER64.ImageBase
                    mov dword ptr qwImageBase+4, eax
                    mov dwImageBase, 0
                    movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER64.Subsystem
                    mov dwSubsystem, eax
                    movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER64.DllCharacteristics
                    mov dwDllCharacteristics, eax
                .ELSE ; ebx points to IMAGE_OPTIONAL_HEADER32
                    mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.ImageBase
                    mov dwImageBase, eax
                    movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER32.Subsystem
                    mov dwSubsystem, eax
                    movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER32.DllCharacteristics
                    mov dwDllCharacteristics, eax
                .ENDIF
            .ELSE
                ;--------------------------------------------------------------
                ; Data Directories in IMAGE_OPTIONAL_HEADER
                ;--------------------------------------------------------------
                mov ebx, pOptionalHeader ; ebx points to IMAGE_OPTIONAL_HEADER
                .IF bPE64 == TRUE ; ebx points to IMAGE_OPTIONAL_HEADER64
                    mov eax, dword ptr [ebx].IMAGE_OPTIONAL_HEADER64.ImageBase
                    mov dword ptr qwImageBase, eax
                    mov eax, dword ptr [ebx+4].IMAGE_OPTIONAL_HEADER64.ImageBase
                    mov dword ptr qwImageBase+4, eax
                    mov dwImageBase, 0
                    movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER64.Subsystem
                    mov dwSubsystem, eax
                    movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER64.DllCharacteristics
                    mov dwDllCharacteristics, eax
                    mov eax, [ebx].IMAGE_OPTIONAL_HEADER64.NumberOfRvaAndSizes
                    mov dwNumberOfRvaAndSizes, eax
                    mov ebx, pOptionalHeader
                    add ebx, SIZEOF_WINDOWS_FIELDS_PE64                    
                    mov pDataDirectories, eax
                .ELSE ; ebx points to IMAGE_OPTIONAL_HEADER32
                    mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.ImageBase
                    mov dwImageBase, eax
                    movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER32.Subsystem
                    mov dwSubsystem, eax
                    movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER32.DllCharacteristics
                    mov dwDllCharacteristics, eax
                    mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes
                    mov dwNumberOfRvaAndSizes, eax
                    mov ebx, pOptionalHeader
                    add ebx, SIZEOF_WINDOWS_FIELDS_PE32
                    mov pDataDirectories, eax
                .ENDIF                
            .ENDIF
        .ENDIF

        ;----------------------------------------------------------------------
        ; Get pointer to SectionTable
        ;----------------------------------------------------------------------
        mov eax, pFileHeader
        add eax, SIZEOF IMAGE_FILE_HEADER
        add eax, dwSizeOfOptionalHeader
        mov pSectionTable, eax
        mov pCurrentSection, eax
        
        mov dwCurrentSection, 0
        mov eax, 0
        .WHILE eax < dwNumberOfSections
            mov ebx, pCurrentSection
            
            ; do stuff with sections
            ; PointerToRawData to get section data
            
            
            add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
            inc dwCurrentSection
            mov eax, dwCurrentSection
        .ENDW
        
    .ELSE
        Invoke PE_SetError, PE_ERROR_ANALYZE_INVALID
        mov eax, NULL
        ret
    .ENDIF
    
    IFDEF DEBUG32
    PrintDec pNTHeader
    PrintDec pFileHeader
    PrintDec pOptionalHeader
    PrintDec dwNumberOfSections
    PrintDec dwSizeOfOptionalHeader
    PrintDec pSectionTable
    PrintText '-------------'
    PrintDec dwMachine
    PrintDec dwNumberOfSections
    PrintDec dwSizeOfOptionalHeader
    PrintDec dwCharacteristics
    PrintDec dwAddressOfEntryPoint
    PrintDec dwSubsystem
    PrintDec dwDllCharacteristics
    
    mov eax, dwNumberOfSections
    mov ebx, SIZEOF IMAGE_SECTION_HEADER
    mul ebx
    DbgDump pSectionTable, eax    
    ENDIF

    ;--------------------------------------------------------------------------
    ; Updated PEINFO with information
    ;--------------------------------------------------------------------------
    mov ebx, hPE
    ; Header pointers
    mov eax, pNTHeader
    mov [ebx].PEINFO.PENTHeader, eax
    mov eax, pFileHeader
    mov [ebx].PEINFO.PEFileHeader, eax
    mov eax, pOptionalHeader
    mov [ebx].PEINFO.PEOptionalHeader, eax
    mov eax, pDataDirectories
    mov [ebx].PEINFO.PEDataDirectories, eax
    mov eax, pSectionTable
    mov [ebx].PEINFO.PESectionTable, eax
    ; Info
    mov eax, dwMachine
    mov [ebx].PEINFO.PEMachine, eax
    mov eax, dwNumberOfSections
    mov [ebx].PEINFO.PESectionCount, eax    
    mov eax, dwSizeOfOptionalHeader
    mov [ebx].PEINFO.PEOptionalHeaderSize, eax
    mov eax, dwCharacteristics
    mov [ebx].PEINFO.PECharacteristics, eax
    and eax, IMAGE_FILE_DLL
    .IF eax == IMAGE_FILE_DLL
        mov [ebx].PEINFO.PEDLL, TRUE
    .ELSE
        mov [ebx].PEINFO.PEDLL, FALSE
    .ENDIF
    mov eax, dwAddressOfEntryPoint
    mov [ebx].PEINFO.PEAddressOfEntryPoint, eax
    .IF bPE64 == TRUE
        mov eax, dword ptr qwImageBase
        mov dword ptr [ebx].PEINFO.PE64ImageBase, eax
        mov eax, dword ptr qwImageBase+4
        mov dword ptr [ebx].PEINFO.PE64ImageBase, eax
    .ELSE
        mov eax, dwImageBase
        mov [ebx].PEINFO.PEImageBase, eax
    .ENDIF
    mov eax, dwSubsystem
    mov [ebx].PEINFO.PESubsystem, eax
    mov eax, dwDllCharacteristics
    mov [ebx].PEINFO.PEDllCharacteristics, eax

    mov eax, hPE
    ret
PE_Analyze ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_Finish - Frees up hPE if PE was processed from memory directly with a call
; to PE_Analyze. If PE was opened as a file via PE_OpenFile, then PE_CloseFile 
; should be used instead of this function.
;------------------------------------------------------------------------------
PE_Finish PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov eax, hPE
    .IF eax != NULL
        Invoke GlobalFree, eax
    .ENDIF
    ret
PE_Finish ENDP

;############################################################################
;  H E A D E R   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; PE_HeaderDOS - returns pointer to IMAGE_DOS_HEADER of PE file
;----------------------------------------------------------------------------
PE_HeaderDOS PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEDOSHeader
    ; eax points to IMAGE_DOS_HEADER
    ret
PE_HeaderDOS ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_HeaderNT - returns pointer to IMAGE_NT_HEADERS of PE file
;----------------------------------------------------------------------------
PE_HeaderNT PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PENTHeader
    ; eax points to IMAGE_NT_HEADERS
    ret
PE_HeaderNT ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_HeaderFile - return pointer to IMAGE_FILE_HEADER of PE file
;----------------------------------------------------------------------------
PE_HeaderFile PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFileHeader
    ; eax points to IMAGE_FILE_HEADER
    ret
PE_HeaderFile ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_HeaderOptional - returns pointer to IMAGE_OPTIONAL_HEADER (32/64)
;----------------------------------------------------------------------------
PE_HeaderOptional PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEOptionalHeader
    ; eax points to IMAGE_OPTIONAL_HEADER (32/64)
    ret
PE_HeaderOptional ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_HeaderSections - returns pointer to array of IMAGE_SECTION_HEADER
;----------------------------------------------------------------------------
PE_HeaderSections PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [eax].PEINFO.PESectionTable
    ; eax points to array of IMAGE_SECTION_HEADER entries
    ret
PE_HeaderSections ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_DirectoryExportTable - returns pointer 
;----------------------------------------------------------------------------
PE_DirectoryExportTable PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    ret
PE_DirectoryExportTable ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_DirectoryImportTable - returns pointer 
;----------------------------------------------------------------------------
PE_DirectoryImportTable PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    ret
PE_DirectoryImportTable ENDP



;############################################################################
;  S E C T I O N   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionsHeaders - returns pointer to array of IMAGE_SECTION_HEADER
;----------------------------------------------------------------------------
PE_SectionsHeaders PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [eax].PEINFO.PESectionTable
    ; eax points to array of IMAGE_SECTION_HEADER entries
    ret
PE_SectionsHeaders ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionHeaderCount - returns no of sections
;----------------------------------------------------------------------------
PE_SectionHeaderCount PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PESectionCount
    ret
PE_SectionHeaderCount ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionHeaderByIndex - returns pointer to section specified by Index
;----------------------------------------------------------------------------
PE_SectionHeaderByIndex PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    LOCAL pHeaderSections:DWORD
     
    .IF dwSectionIndex > 96d ; max sections allowed as per MS COFF docs
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_SectionHeaderCount, hPE
    .IF dwSectionIndex >= eax
        xor eax, eax
        ret
    .ENDIF    
    
    Invoke PE_HeaderSections, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pHeaderSections, eax

    mov eax, dwSectionIndex
    mov ebx, SIZEOF IMAGE_SECTION_HEADER
    mul ebx
    add eax, pHeaderSections

    ret
PE_SectionHeaderByIndex ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionHeaderByName - returns pointer to section specified by Name
;----------------------------------------------------------------------------
PE_SectionHeaderByName PROC USES EBX hPE:DWORD, lpszSectionName:DWORD
    LOCAL pHeaderSections:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL nSections:DWORD
    LOCAL nSection:DWORD
    
    .IF lpszSectionName == NULL
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_HeaderSections, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pHeaderSections, eax
    
    Invoke PE_SectionHeaderCount, hPE
    mov ebx, pCurrentSection
    mov nSections, eax
    mov nSection, 0
    mov eax, 0
    .WHILE eax < nSection    
        .IF [ebx].IMAGE_SECTION_HEADER.Name1 != 0
            lea ebx, [ebx].IMAGE_SECTION_HEADER.Name1
            Invoke lstrcmp, ebx, lpszSectionName
            .IF eax == 0 ; match
                mov eax, pCurrentSection
                ret
            .ENDIF
        .ENDIF
        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nSection
        mov eax, nSection
    .ENDW
    
    xor eax, eax
    ret
PE_SectionHeaderByName ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionHeaderByType - returns pointer to section specified by Type
;----------------------------------------------------------------------------
PE_SectionHeaderByType PROC USES EBX hPE:DWORD, dwSectionType:DWORD
    LOCAL pHeaderSections:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL nSections:DWORD
    LOCAL nSection:DWORD
    
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
    mov nSections, eax
    mov nSection, 0
    mov eax, 0
    .WHILE eax < nSections
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



;############################################################################
;  I N F O   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; PE_Machine - returns machine id in eax
;----------------------------------------------------------------------------
PE_Machine PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMachine
    ret
PE_Machine ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_Characteristics - returns characteristics bit flags in eax
;----------------------------------------------------------------------------
PE_Characteristics PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PECharacteristics
    ret
PE_Characteristics ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_AddressOfEntryPoint - returns OEP in eax
;----------------------------------------------------------------------------
PE_AddressOfEntryPoint PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEAddressOfEntryPoint
    ret
PE_AddressOfEntryPoint ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_ImageBase - returns imagebase in eax for PE32, eax:edx for PE32+ (PE64)
;----------------------------------------------------------------------------
PE_ImageBase PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PE64
    .IF eax == TRUE
        mov eax, dword ptr [ebx].PEINFO.PE64ImageBase
        mov edx, dword ptr [ebx+4].PEINFO.PE64ImageBase
    .ELSE
        mov eax, [ebx].PEINFO.PEImageBase
        xor edx, edx
    .ENDIF
    ret
PE_ImageBase ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_Subsystem - returns subsystem id in eax
;----------------------------------------------------------------------------
PE_Subsystem PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PESubsystem
    ret
PE_Subsystem ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_DllCharacteristics - returns dll characteristics bit flags in eax
;----------------------------------------------------------------------------
PE_DllCharacteristics PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEDllCharacteristics
    ret
PE_DllCharacteristics ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_IsDll - returns TRUE if DLL or FALSE otherwise
;----------------------------------------------------------------------------
PE_IsDll PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEDLL
    ret
PE_IsDll ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_Is64 - returns TRUE if PE32+ (PE64) or FALSE if PE32
;----------------------------------------------------------------------------
PE_Is64 PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PE64
    ret
PE_Is64 ENDP



;############################################################################
;  E R R O R   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SetError
;----------------------------------------------------------------------------
PE_SetError PROC dwError:DWORD
    mov dwError, eax
    mov PELIB_ErrorNo, eax
    xor eax, eax
    ret
PE_SetError ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_GetError
;----------------------------------------------------------------------------
PE_GetError PROC
    mov eax, PELIB_ErrorNo
    ret
PE_GetError ENDP



;############################################################################
;  I N T E R N A L   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; Checks the PE signatures to determine if they are valid
;----------------------------------------------------------------------------
PESignature PROC USES EBX pPE:DWORD
    mov ebx, pPE
    movzx eax, word ptr [ebx].IMAGE_DOS_HEADER.e_magic
    .IF ax == MZ_SIGNATURE
        add ebx, [ebx].IMAGE_DOS_HEADER.e_lfanew
        ; ebx is pointer to IMAGE_NT_HEADERS now
        mov eax, [ebx].IMAGE_NT_HEADERS.Signature
        PrintDec eax
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



END






















