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

;DEBUG32 EQU 1
;IFDEF DEBUG32
;    PRESERVEXMMREGS equ 1
;    includelib M:\Masm32\lib\Debug32.lib
;    DBG32LIB equ 1
;    DEBUGEXE textequ <'M:\Masm32\DbgWin.exe'>
;    include M:\Masm32\include\debug32.inc
;ENDIF

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

PEIncreaseFileSize      PROTO :DWORD, :DWORD
PEDecreaseFileSize      PROTO :DWORD, :DWORD
PEDwordToAscii          PROTO :DWORD, :DWORD
PE_SetError             PROTO :DWORD, :DWORD

PUBLIC PELIB_ErrorNo

;-------------------------------------------------------------------------
; Structures for internal use
;-------------------------------------------------------------------------

IFNDEF PEINFO
PEINFO                      STRUCT
    PEOpenMode              DD 0
    PEHandle                DD 0
    PEFilename              DB MAX_PATH DUP (0)
    PEFilesize              DD 0
    PEVersion               DD 0
    PE64                    DD 0
    PEDLL                   DD 0
    PEDOSHeader             DD 0
    PERichHeader            DD 0
    PERichCompIDs           DD 0
    PENTHeader              DD 0
    PEFileHeader            DD 0
    PEOptionalHeader        DD 0
    PESectionTable          DD 0
    PESectionCount          DD 0
    PEOptionalHeaderSize    DD 0
    PEImageBase             DD 0
    PE64ImageBase           DQ 0
    PENumberOfRvaAndSizes   DD 0
    PEDataDirectories       DD 0
    PEExportCount           DD 0
    PEExportDirectoryTable  DD 0
    PEExportAddressTable    DD 0
    PEExportNamePointerTable DD 0
    PEExportOrdinalTable    DD 0
    PEExportNameTable       DD 0
    PEImportDirectoryCount  DD 0
    PEImportDirectoryTable  DD 0
    PEImportLookupTable     DD 0
    PEImportNameTable       DD 0
    PEImportAddressTable    DD 0
    PEResourceDirectoryTable DD 0
    PEResourceDirectoryEntries DD 0
    PEResourceDirectoryString DD 0
    PEResourceDataEntry     DD 0
    PEExceptionTable        DD 0
    PECertificateTable      DD 0
    PEBaseRelocationTable   DD 0
    PEDebugData             DD 0
    PEGlobalPtr             DD 0
    PETLSTable              DD 0
    PELoadConfigTable       DD 0
    PEBoundImportTable      DD 0
    PEDelayImportDescriptor DD 0
    PECLRRuntimeHeader      DD 0
    PEMemMapPtr             DD 0
    PEMemMapHandle          DD 0
    PEFileHandle            DD 0
PEINFO                      ENDS
ENDIF

.CONST



.DATA
PELIB_ErrorNo               DD PE_ERROR_NO_HANDLE ; Global to store error no


.CODE
PE_ALIGN
;------------------------------------------------------------------------------
; PE_OpenFile - Opens a PE file (exe/dll/ocx/cpl etc)
; Returns: TRUE or FALSE. If TRUE a PE handle (hPE) is stored in the variable
; pointed to by lpdwPEHandle. If FALSE, use PE_GetError to get further info.
;
; Note: Calls PE_Analyze to process the PE file. Use PE_CloseFile when finished
;------------------------------------------------------------------------------
PE_OpenFile PROC USES EBX lpszPEFilename:DWORD, bReadOnly:DWORD, lpdwPEHandle:DWORD
    LOCAL hPE:DWORD
    LOCAL hPEFile:DWORD
    LOCAL PEMemMapHandle:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL PEFilesize:DWORD
    LOCAL PEVersion:DWORD
    
    IFDEF DEBUG32
    PrintText 'PE_OpenFile'
    ENDIF
    
    .IF lpdwPEHandle == NULL
        Invoke PE_SetError, NULL, PE_ERROR_NO_HANDLE
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszPEFilename == NULL
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_FILE
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF

    ;--------------------------------------------------------------------------
    ; Open file for read only or read/write access
    ;--------------------------------------------------------------------------
    .IF bReadOnly == TRUE
        Invoke CreateFile, lpszPEFilename, GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    .ELSE
        Invoke CreateFile, lpszPEFilename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    .ENDIF
    .IF eax == INVALID_HANDLE_VALUE
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_FILE
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    mov hPEFile, eax ; store file handle
    
    ;--------------------------------------------------------------------------
    ; Get file size and verify its not too low or too high in size
    ;--------------------------------------------------------------------------
    Invoke GetFileSize, hPEFile, NULL
    .IF eax < 268d ; https://www.bigmessowires.com/2015/10/08/a-handmade-executable-file/
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_SIZE_LOW
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ELSEIF eax > 1FFFFFFFh ; 536,870,911 536MB+ - rare to be this size or larger
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_SIZE_HIGH
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret    
    .ENDIF
    mov PEFilesize, eax ; file size

    ;--------------------------------------------------------------------------
    ; Create file mapping of entire file
    ;--------------------------------------------------------------------------
    .IF bReadOnly == TRUE
        Invoke CreateFileMapping, hPEFile, NULL, PAGE_READONLY, 0, 0, NULL ; Create memory mapped file
    .ELSE
        Invoke CreateFileMapping, hPEFile, NULL, PAGE_READWRITE, 0, 0, NULL ; Create memory mapped file
    .ENDIF
    .IF eax == NULL
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_MAP
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    mov PEMemMapHandle, eax ; store mapping handle
    
    ;--------------------------------------------------------------------------
    ; Create view of file
    ;--------------------------------------------------------------------------
    .IF bReadOnly == TRUE
        Invoke MapViewOfFileEx, PEMemMapHandle, FILE_MAP_READ, 0, 0, 0, NULL
    .ELSE
        Invoke MapViewOfFileEx, PEMemMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0, NULL
    .ENDIF    
    .IF eax == NULL
        Invoke CloseHandle, PEMemMapHandle
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_VIEW
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    mov PEMemMapPtr, eax ; store map view pointer

    ;--------------------------------------------------------------------------
    ; Check PE file signature - to make sure MZ and PE sigs are located
    ;--------------------------------------------------------------------------
    Invoke PESignature, PEMemMapPtr
    .IF eax == PE_INVALID
        ;----------------------------------------------------------------------
        ; Invalid PE file, so close all handles and return error
        ;----------------------------------------------------------------------
        Invoke UnmapViewOfFile, PEMemMapPtr
        Invoke CloseHandle, PEMemMapHandle
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_INVALID
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ELSE ; eax == PE_ARCH_32 || eax == PE_ARCH_64
        ;----------------------------------------------------------------------
        ; PE file is valid. So we process PE file and get pointers and other 
        ; information and store in a 'handle' (hPE) that we return. 
        ; Handle is a pointer to a PEINFO struct that stores PE file info.
        ;----------------------------------------------------------------------
        Invoke PE_Analyze, PEMemMapPtr, lpdwPEHandle
        .IF eax == FALSE
            ;------------------------------------------------------------------
            ; Error processing PE file, so close all handles and return error
            ;------------------------------------------------------------------        
            Invoke UnmapViewOfFile, PEMemMapPtr
            Invoke CloseHandle, PEMemMapHandle
            Invoke CloseHandle, hPEFile
            xor eax, eax
            ret
        .ENDIF
    .ENDIF
    
    ;--------------------------------------------------------------------------
    ; Success in processing PE file. Store additional information like file and
    ; map handles and filesize in our PEINFO struct (hPE) if we reach here.
    ;--------------------------------------------------------------------------
    .IF lpdwPEHandle == NULL
        Invoke UnmapViewOfFile, PEMemMapPtr
        Invoke CloseHandle, PEMemMapHandle
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_INVALID    
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF       
    
    mov ebx, lpdwPEHandle
    mov eax, [ebx]
    mov hPE, eax
    mov ebx, hPE
    mov eax, lpdwPEHandle
    mov [ebx].PEINFO.PEHandle, eax
    mov eax, bReadOnly
    mov [ebx].PEINFO.PEOpenMode, eax        
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
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    mov ebx, lpdwPEHandle
    mov eax, hPE
    mov [ebx], eax
    
    ;mov eax, hPE ; Return handle for our user to store and use in other functions
    mov eax, TRUE
    ret
PE_OpenFile ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_CloseFile - Close PE File
; Returns: None
;------------------------------------------------------------------------------
PE_CloseFile PROC USES EBX hPE:DWORD

    IFDEF DEBUG32
    PrintText 'PE_CloseFile'
    ENDIF
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF

    mov ebx, hPE
    mov ebx, [ebx].PEINFO.PEHandle
    .IF ebx != 0
        mov eax, 0 ; null out hPE handle if it exists
        mov [ebx], eax
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
    
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    xor eax, eax
    ret
PE_CloseFile ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_Analyze - Process memory mapped PE file 
; Returns: TRUE or FALSE. If TRUE a PE handle (hPE) is stored in the variable
; pointed to by lpdwPEHandle. If FALSE, use PE_GetError to get further info.
;
; Can be used directly on memory region where PE is already loaded/mapped
;
; PE_Analyze is also called by PE_OpenFile.
; Note: Use PE_Finish when finished with PE file if using PE_Analyze directly.
;------------------------------------------------------------------------------
PE_Analyze PROC USES EBX EDX pPEInMemory:DWORD, lpdwPEHandle:DWORD
    LOCAL hPE:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pFileHeader:DWORD
    LOCAL pOptionalHeader:DWORD
    LOCAL pDataDirectories:DWORD
    LOCAL pSectionTable:DWORD
    LOCAL pImportDirectoryTable:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwNumberOfSections:DWORD
    LOCAL dwSizeOfOptionalHeader:DWORD
    LOCAL dwNumberOfRvaAndSizes:DWORD
    LOCAL dwCurrentSection:DWORD
    LOCAL bPE64:DWORD
    LOCAL dwRVA:DWORD
    LOCAL dwOffset:DWORD
    
    IFDEF DEBUG32
    PrintText 'PE_Analyze'
    ENDIF    
    
    .IF lpdwPEHandle == NULL
        Invoke PE_SetError, NULL, PE_ERROR_NO_HANDLE
        xor eax, eax
        ret
    .ENDIF    
    
    .IF pPEInMemory == NULL
        Invoke PE_SetError, NULL, PE_ERROR_ANALYZE_NULL
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    
    mov eax, pPEInMemory
    mov PEMemMapPtr, eax       
    
    ;--------------------------------------------------------------------------
    ; Alloc mem for our PE Handle (PEINFO)
    ;--------------------------------------------------------------------------
    Invoke GlobalAlloc, GMEM_FIXED or GMEM_ZEROINIT, SIZEOF PEINFO
    .IF eax == NULL
        Invoke PE_SetError, NULL, PE_ERROR_ANALYZE_ALLOC
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    mov hPE, eax
    
    mov edx, hPE
    mov eax, PEMemMapPtr
    mov [edx].PEINFO.PEMemMapPtr, eax
    mov [edx].PEINFO.PEDOSHeader, eax

    ; Process PE in memory
    mov eax, PEMemMapPtr
    mov ebx, eax ; ebx points to IMAGE_DOS_HEADER in memory
    .IF [ebx].IMAGE_DOS_HEADER.e_lfanew == 0
        Invoke PE_SetError, hPE, PE_ERROR_ANALYZE_INVALID
        .IF hPE != NULL
            Invoke GlobalFree, hPE
        .ENDIF
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF    
    
    ;--------------------------------------------------------------------------
    ; Get headers: NT, File, Optional & other useful fields
    ;--------------------------------------------------------------------------
    ; ebx points to IMAGE_DOS_HEADER in memory
    add eax, [ebx].IMAGE_DOS_HEADER.e_lfanew
    mov [edx].PEINFO.PENTHeader, eax
    mov ebx, eax ; ebx points to IMAGE_NT_HEADERS
    lea eax, [ebx].IMAGE_NT_HEADERS.FileHeader
    mov [edx].PEINFO.PEFileHeader, eax
    mov pFileHeader, eax
    lea eax, [ebx].IMAGE_NT_HEADERS.OptionalHeader
    mov [edx].PEINFO.PEOptionalHeader, eax
    mov pOptionalHeader, eax
    mov ebx, pFileHeader ; ebx points to IMAGE_FILE_HEADER
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.NumberOfSections
    mov [edx].PEINFO.PESectionCount, eax
    mov dwNumberOfSections, eax
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.SizeOfOptionalHeader
    mov [edx].PEINFO.PEOptionalHeaderSize, eax
    mov dwSizeOfOptionalHeader, eax
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.Characteristics
    and eax, IMAGE_FILE_DLL
    .IF eax == IMAGE_FILE_DLL
        mov [edx].PEINFO.PEDLL, TRUE
    .ELSE
        mov [edx].PEINFO.PEDLL, FALSE
    .ENDIF        
    
    .IF dwSizeOfOptionalHeader == 0
        mov pOptionalHeader, 0
        mov pDataDirectories, 0
        mov dwNumberOfRvaAndSizes, 0
        mov bPE64, FALSE
    .ELSE
        ;----------------------------------------------------------------------
        ; Get PE32/PE32+ magic number
        ;----------------------------------------------------------------------
        mov ebx, pOptionalHeader; ebx points to IMAGE_OPTIONAL_HEADER
        movzx eax, word ptr [ebx]
        .IF eax == IMAGE_NT_OPTIONAL_HDR32_MAGIC ; PE32
            mov ebx, hPE
            mov [edx].PEINFO.PE64, FALSE
            mov bPE64, FALSE
        .ELSEIF eax == IMAGE_NT_OPTIONAL_HDR64_MAGIC ; PE32+ (PE64)
            mov ebx, hPE
            mov [edx].PEINFO.PE64, TRUE
            mov bPE64, TRUE
        .ELSE ; ROM or something else
            Invoke PE_SetError, hPE, PE_ERROR_ANALYZE_INVALID
            .IF hPE != NULL
                Invoke GlobalFree, hPE
            .ENDIF
            mov ebx, lpdwPEHandle
            mov eax, 0
            mov [ebx], eax
            xor eax, eax
            ret
        .ENDIF
        
        mov eax, dwSizeOfOptionalHeader
        .IF eax == 28 || eax == 24
            ;------------------------------------------------------------------
            ; Standard fields in IMAGE_OPTIONAL_HEADER
            ;------------------------------------------------------------------
            mov pDataDirectories, 0
            mov dwNumberOfRvaAndSizes, 0
        .ELSEIF eax == 68 || eax == 88 ; Windows specific fields in IMAGE_OPTIONAL_HEADER
            ;------------------------------------------------------------------
            ; Windows specific fields in IMAGE_OPTIONAL_HEADER
            ; Get ImageBase, Subsystem, DllCharacteristics
            ;------------------------------------------------------------------
            mov pDataDirectories, 0
            mov dwNumberOfRvaAndSizes, 0
            mov ebx, pOptionalHeader ; ebx points to IMAGE_OPTIONAL_HEADER
            .IF bPE64 == TRUE ; ebx points to IMAGE_OPTIONAL_HEADER64
                mov eax, dword ptr [ebx].IMAGE_OPTIONAL_HEADER64.ImageBase
                mov dword ptr [edx].PEINFO.PE64ImageBase, eax
                mov eax, dword ptr [ebx+4].IMAGE_OPTIONAL_HEADER64.ImageBase
                mov dword ptr [edx+4].PEINFO.PE64ImageBase, eax 
                mov [edx].PEINFO.PEImageBase, 0
             .ELSE ; ebx points to IMAGE_OPTIONAL_HEADER32
                mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.ImageBase
                mov [edx].PEINFO.PEImageBase, eax
            .ENDIF
        .ELSE
            ;------------------------------------------------------------------
            ; Data Directories in IMAGE_OPTIONAL_HEADER
            ;------------------------------------------------------------------
            mov ebx, pOptionalHeader ; ebx points to IMAGE_OPTIONAL_HEADER
            .IF bPE64 == TRUE ; ebx points to IMAGE_OPTIONAL_HEADER64
                mov eax, dword ptr [ebx].IMAGE_OPTIONAL_HEADER64.ImageBase
                mov dword ptr [edx].PEINFO.PE64ImageBase, eax
                mov eax, dword ptr [ebx+4].IMAGE_OPTIONAL_HEADER64.ImageBase
                mov dword ptr [edx+4].PEINFO.PE64ImageBase, eax 
                mov [edx].PEINFO.PEImageBase, 0
                mov eax, [ebx].IMAGE_OPTIONAL_HEADER64.NumberOfRvaAndSizes
                mov [edx].PEINFO.PENumberOfRvaAndSizes, eax
                mov dwNumberOfRvaAndSizes, eax
                mov ebx, pOptionalHeader
                add ebx, SIZEOF_STANDARD_FIELDS_PE64
                add ebx, SIZEOF_WINDOWS_FIELDS_PE64                    
                mov pDataDirectories, ebx
            .ELSE ; ebx points to IMAGE_OPTIONAL_HEADER32
                mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.ImageBase
                mov [edx].PEINFO.PEImageBase, eax
                mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes
                mov [edx].PEINFO.PENumberOfRvaAndSizes, eax
                mov dwNumberOfRvaAndSizes, eax
                mov ebx, pOptionalHeader
                add ebx, SIZEOF_STANDARD_FIELDS_PE32
                add ebx, SIZEOF_WINDOWS_FIELDS_PE32
                mov pDataDirectories, ebx
            .ENDIF                
        .ENDIF
    .ENDIF
    
    ;--------------------------------------------------------------------------
    ; Get pointer to SectionTable
    ;--------------------------------------------------------------------------
    mov eax, pFileHeader
    add eax, SIZEOF IMAGE_FILE_HEADER
    add eax, dwSizeOfOptionalHeader
    mov [edx].PEINFO.PESectionTable, eax
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
    
    ;--------------------------------------------------------------------------
    ; Get Data Directories
    ;--------------------------------------------------------------------------
    IFDEF DEBUG32
    mov eax, dwNumberOfRvaAndSizes
    mov ebx, SIZEOF IMAGE_DATA_DIRECTORY
    mul ebx
    DbgDump pDataDirectories, eax
    ENDIF
    
    mov pImportDirectoryTable, 0
    
    .IF pDataDirectories != 0
        mov edx, hPE
        .IF dwNumberOfRvaAndSizes > 0 ; Export Table
            mov ebx, pDataDirectories
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEExportDirectoryTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 1 ; Import Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEImportDirectoryTable, eax
                mov pImportDirectoryTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 2 ; Resource Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEResourceDirectoryTable, eax
            .ENDIF
        .ENDIF            
        .IF dwNumberOfRvaAndSizes > 3 ; Exception Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEExceptionTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 4 ; Certificate Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PECertificateTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 5 ; Base Relocation Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEBaseRelocationTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 6 ; Debug Data
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEDebugData, eax
            .ENDIF
        .ENDIF
        ;.IF dwNumberOfRvaAndSizes > 7 ; Data Directory Architecture
            ;mov ebx, pDataDirectories
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            ;.IF eax != 0
            ;    add eax, PEMemMapPtr
            ;    mov pDataDirArchitecture, eax
            ;.ENDIF
        ;.ENDIF
        .IF dwNumberOfRvaAndSizes > 8 ; Global Ptr
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEGlobalPtr, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 9 ; TLS Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PETLSTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 10 ; Load Config Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PELoadConfigTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 11 ; Bound Import Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEBoundImportTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 12 ; Import Address Table
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEImportAddressTable, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 13 ; Delay Import Descriptor
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEDelayImportDescriptor, eax
            .ENDIF
        .ENDIF
        .IF dwNumberOfRvaAndSizes > 14 ; CLR Runtime Header
            mov ebx, pDataDirectories
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PECLRRuntimeHeader, eax
            .ENDIF
        .ENDIF
        ;.IF dwNumberOfRvaAndSizes > 15 ; DataDir Reserved
            ;mov ebx, pDataDirectories
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;add ebx, SIZEOF IMAGE_DATA_DIRECTORY
            ;mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            ;.IF eax != 0
            ;    add eax, PEMemMapPtr
            ;    mov pDataDirReserved, eax
            ;.ENDIF
        ;.ENDIF
    .ENDIF
    
    ;--------------------------------------------------------------------------
    ; Import 
    ;--------------------------------------------------------------------------
    .IF pImportDirectoryTable != 0
        mov eax, 0
        mov ebx, pImportDirectoryTable
        .WHILE [ebx].IMAGE_IMPORT_DESCRIPTOR.Characteristics != 0
            inc eax
            add ebx, SIZEOF IMAGE_IMPORT_DESCRIPTOR
        .ENDW
        mov edx, hPE
        mov [edx].PEINFO.PEImportDirectoryCount, eax 
    .ENDIF

    IFDEF DEBUG32
    mov eax, dwNumberOfSections
    mov ebx, SIZEOF IMAGE_SECTION_HEADER
    mul ebx
    DbgDump pSectionTable, eax    
    ENDIF

    Invoke PE_HeaderRich, hPE
    .IF eax != 0
        mov edx, hPE
        mov [edx].PEINFO.PERichHeader, eax
        Invoke PE_RichSignatureCompIDs, hPE
        .IF eax != 0
            mov edx, hPE
            mov [edx].PEINFO.PERichCompIDs, eax
        .ENDIF
    .ENDIF


    ;--------------------------------------------------------------------------
    ; Update PEINFO handle information
    ;--------------------------------------------------------------------------
    mov edx, hPE
    mov eax, lpdwPEHandle
    mov [edx].PEINFO.PEHandle, eax

    mov ebx, lpdwPEHandle
    mov eax, hPE
    mov [ebx], eax

    mov eax, TRUE
    ret
PE_Analyze ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_Finish - Frees up hPE if PE was processed from memory directly with a call
; to PE_Analyze. If PE was opened as a file via PE_OpenFile, then PE_CloseFile 
; should be used instead of this function.
; Returns: None
;------------------------------------------------------------------------------
PE_Finish PROC USES EBX hPE:DWORD

    IFDEF DEBUG32
    PrintText 'PE_Finish'
    ENDIF
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov ebx, [ebx].PEINFO.PEHandle
    .IF ebx != 0
        mov eax, 0 ; null out hPE handle if it exists
        mov [ebx], eax
    .ENDIF
        
    mov eax, hPE
    .IF eax != NULL
        Invoke GlobalFree, eax
    .ENDIF
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    xor eax, eax
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
    mov eax, [ebx].PEINFO.PESectionTable
    ; eax points to array of IMAGE_SECTION_HEADER entries
    ret
PE_HeaderSections ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_HeaderRich - returns pointer to rich signature in PE file or NULL
; http://bytepointer.com/articles/the_microsoft_rich_header.htm
;----------------------------------------------------------------------------
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

PE_ALIGN
;----------------------------------------------------------------------------
; PE_HeaderStub - returns pointer to DOS Stub
;----------------------------------------------------------------------------
PE_HeaderStub PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderDOS, hPE
    .IF eax == 0
        ret
    .ENDIF
    add eax, SIZEOF IMAGE_DOS_HEADER
    ret
PE_HeaderStub ENDP





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
    mov eax, [ebx].PEINFO.PESectionTable
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
; PE_SectionHeaderByIndex - Get section specified by dwSectionIndex
; Returns: pointer to section IMAGE_SECTION_HEADER or NULL
;----------------------------------------------------------------------------
PE_SectionHeaderByIndex PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    LOCAL pHeaderSections:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF    
    
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
; PE_SectionHeaderByName - Get section specified by lpszSectionName
; Returns: pointer to section IMAGE_SECTION_HEADER or NULL
;----------------------------------------------------------------------------
PE_SectionHeaderByName PROC USES EBX hPE:DWORD, lpszSectionName:DWORD
    LOCAL pHeaderSections:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL lpszName:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nSection:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszSectionName == NULL
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
    mov nTotalSections, eax
    mov ebx, pCurrentSection
    mov nSection, 0
    mov eax, 0
    .WHILE eax < nTotalSections    
        lea eax, [ebx].IMAGE_SECTION_HEADER.Name1
        mov lpszName, eax
        Invoke lstrcmp, lpszName, lpszSectionName
        .IF eax == 0 ; match
            mov eax, pCurrentSection
            ret
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
; PE_SectionHeaderByType - Get section specified by dwSectionType
; Returns: pointer to section IMAGE_SECTION_HEADER or NULL
;----------------------------------------------------------------------------
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

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionHeaderByAddr - Get section that has RVA of dwAddress
; Returns: pointer to section IMAGE_SECTION_HEADER or NULL
;----------------------------------------------------------------------------
PE_SectionHeaderByAddr PROC USES EBX EDX hPE:DWORD, dwAddress:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nCurrentSection:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwSectionSize:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PESectionCount
    mov nTotalSections, eax
    mov eax, [ebx].PEINFO.PESectionTable
    mov pCurrentSection, eax

    mov ebx, pCurrentSection
    mov edx, dwAddress
    mov eax, 0
    mov nCurrentSection, 0
    .WHILE eax < nTotalSections
        mov eax, [ebx].IMAGE_SECTION_HEADER.Misc.VirtualSize
        .IF eax == 0
            mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
        .ENDIF
        mov dwSectionSize, eax
    
        mov eax, [ebx].IMAGE_SECTION_HEADER.VirtualAddress
        .IF eax <= edx
            add eax, dwSectionSize
            .IF eax > edx
                mov eax, pCurrentSection
                ret
            .ENDIF
        .ENDIF

        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nCurrentSection
        mov eax, nCurrentSection
    .ENDW
    
    xor eax, eax
    ret
PE_SectionHeaderByAddr ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionName - Get section name for specified section (dwSectionIndex)
; Returns: pointer to section name or NULL
;----------------------------------------------------------------------------
PE_SectionName PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_SectionHeaderByIndex, hPE, dwSectionIndex
    .IF eax == 0
        xor eax, eax
        ret
    .ENDIF
    mov ebx, eax
    lea ebx, [ebx].IMAGE_SECTION_HEADER.Name1
    ret
PE_SectionName ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionSizeRaw - Get section raw size for specified section (dwSectionIndex)
; Returns: size of section or 0
;----------------------------------------------------------------------------
PE_SectionSizeRaw PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_SectionHeaderByIndex, hPE, dwSectionIndex
    .IF eax == 0
        xor eax, eax
        ret
    .ENDIF
    mov ebx, eax
    mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
    ret
PE_SectionSizeRaw ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionCharacteristics - Get section characteristics for specified 
; section (dwSectionIndex)
; Returns: section Characteristics or NULL
;----------------------------------------------------------------------------
PE_SectionCharacteristics PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_SectionHeaderByIndex, hPE, dwSectionIndex
    .IF eax == 0
        xor eax, eax
        ret
    .ENDIF
    mov ebx, eax
    mov eax, [ebx].IMAGE_SECTION_HEADER.Characteristics
    ret
PE_SectionCharacteristics ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionType - Get section characteristics for specified 
; section (dwSectionIndex) and return type of section: executable, writable 
; data, read only data, uninitialized data
; Returns: 0 for unknow, 1 for EX, 2 for WD, 3 for RD, 4 for 0D
;----------------------------------------------------------------------------
PE_SectionType PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD
    LOCAL Characteristics:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_SectionCharacteristics, hPE, dwSectionIndex
    .IF eax == 0
        ret
    .ENDIF
    mov Characteristics, eax
    
    and eax, (IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE)
    .IF eax == (IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE)
        mov eax, 1 ; code execution
        ret
    .ENDIF
    
    mov eax, Characteristics
    and eax, (IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE)
    .IF eax == (IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE)
        mov eax, 2 ; writable data
        ret
    .ENDIF
    
    mov eax, Characteristics
    and eax, (IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ)
    .IF eax == (IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ)
        mov eax, 3 ; readonly data
        ret
    .ENDIF
    
    mov eax, Characteristics
    and eax, (IMAGE_SCN_CNT_UNINITIALIZED_DATA or IMAGE_SCN_MEM_READ)
    .IF eax == (IMAGE_SCN_CNT_UNINITIALIZED_DATA or IMAGE_SCN_MEM_READ)
        mov eax, 4 ; uninitialized data like .bss
        ret
    .ENDIF
    
    ret
PE_SectionType ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionDataByIndex - Get pointer to section's raw data 
; Returns: pointer to section data or null
;----------------------------------------------------------------------------
PE_SectionDataByIndex PROC USES EBX hPE:DWORD, dwSectionIndex:DWORD, lpdwSectionDataSize:DWORD
    LOCAL pSectionHeader:DWORD
    LOCAL pSectionData:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwSizeSectionData:DWORD
    
    Invoke PE_SectionHeaderByIndex, hPE, dwSectionIndex
    .IF eax == 0
        ret
    .ENDIF
    mov pSectionHeader, eax
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    
    mov ebx, pSectionHeader
    mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
    ;.IF eax == 0
    ;    mov eax, [ebx].IMAGE_SECTION_HEADER.Misc.VirtualSize
    ;.ENDIF
    mov dwSizeSectionData, eax
    mov eax, [ebx].IMAGE_SECTION_HEADER.PointerToRawData
    add eax, PEMemMapPtr
    mov pSectionData, eax
    
    .IF lpdwSectionDataSize != 0
        mov ebx, lpdwSectionDataSize
        mov eax, dwSizeSectionData
        mov [ebx], eax
    .ENDIF

    mov eax, pSectionData
    ret
PE_SectionDataByIndex ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionDataByName - Get pointer to section's raw data 
; Returns: pointer to section data or null
;----------------------------------------------------------------------------
PE_SectionDataByName PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, lpdwSectionDataSize:DWORD
    LOCAL pSectionHeader:DWORD
    LOCAL pSectionData:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwSizeSectionData:DWORD
    
    Invoke PE_SectionHeaderByName, hPE, lpszSectionName
    .IF eax == 0
        ret
    .ENDIF
    mov pSectionHeader, eax
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    
    mov ebx, pSectionHeader
    mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
    mov dwSizeSectionData, eax
    mov eax, [ebx].IMAGE_SECTION_HEADER.PointerToRawData
    add eax, PEMemMapPtr
    mov pSectionData, eax
    
    .IF lpdwSectionDataSize != 0
        mov ebx, lpdwSectionDataSize
        mov eax, dwSizeSectionData
        mov [ebx], eax
    .ENDIF

    mov eax, pSectionData
    ret
PE_SectionDataByName ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionAdd - Add a new section header to end of section table and a new
; section of specified size and characteristics to end of PE file.
; Returns: TRUE if successful or FALSE otherwise.
;
; Note: If function fails and error is PE_ERROR_SECTION_ADD, then this is a
; fatal error in which the PE file will be closed and the hPE handle will
; be set to NULL. 
;----------------------------------------------------------------------------
PE_SectionAdd PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, dwSectionSize:DWORD, dwSectionCharacteristics:DWORD
    LOCAL dwNewFileSize:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF dwSectionSize == 0
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFilesize
    add eax, dwSectionSize
    add eax, SIZEOF IMAGE_SECTION_HEADER
    mov dwNewFileSize, eax
    Invoke PEIncreaseFileSize, hPE, dwNewFileSize
    .IF eax == TRUE
        ; increment section count in PEINFO and in PE file
        ; adjust offsets and stuff in section header
        ; move everything after section table + SIZEOF IMAGE_SECTION_HEADER
    .ELSE
        Invoke PE_SetError, hPE, PE_ERROR_SECTION_ADD
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    mov eax, TRUE
    ret
PE_SectionAdd ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionDelete - Delete an existing section (by name or index)
; Returns: TRUE if successful or FALSE otherwise.
;
; Note: If function fails and error is PE_ERROR_SECTION_DEL, then this is a
; fatal error in which the PE file will be closed and the hPE handle will
; be set to NULL. 
;----------------------------------------------------------------------------
PE_SectionDelete PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, dwSectionIndex:DWORD
    LOCAL dwNewFileSize:DWORD
    LOCAL dwSectionSize:DWORD
    LOCAL nSection:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszSectionName != NULL ; section name to index 
        ; find section name
    .ELSE ; already have index
        mov eax, dwSectionIndex
    .ENDIF
    mov nSection, eax
    
    ; get existing section size
    ; 
    mov dwSectionSize, eax
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFilesize
    sub eax, dwSectionSize
    sub eax, SIZEOF IMAGE_SECTION_HEADER
    mov dwNewFileSize, eax    
    
    ; Move data down by - SIZEOF IMAGE_SECTION_HEADER
    ; adjust any stuff that needs adjusting
    
    Invoke PEDecreaseFileSize, hPE, dwNewFileSize
    .IF eax == TRUE
        ; Decrement section count in PEINFO and in PE file
        ; adjust offsets and stuff in section header
    .ELSE
        Invoke PE_SetError, hPE, PE_ERROR_SECTION_DEL
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    mov eax, TRUE
    ret
PE_SectionDelete ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionInsert - Add and insert a new section.
; Returns: TRUE if successful or FALSE otherwise.
;
; Note: If function fails and error is PE_ERROR_SECTION_INS, then this is a
; fatal error in which the PE file will be closed and the hPE handle will
; be set to NULL. 
;----------------------------------------------------------------------------
PE_SectionInsert PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, dwSectionSize:DWORD, dwSectionCharacteristics:DWORD, dwSectionIndex:DWORD
    LOCAL dwNewFileSize:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF dwSectionSize == 0
        xor eax, eax
        ret
    .ENDIF
    
    ; Call PE_SectionAdd then PE_SectionMove?
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    mov eax, TRUE
    ret
PE_SectionInsert ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SectionMove - Move section (by name or index) to section (by name or index)
; Returns: TRUE if successful or FALSE otherwise.
;
; Note: If function fails and error is PE_ERROR_SECTION_MOVE, then this is a
; fatal error in which the PE file will be closed and the hPE handle will
; be set to NULL. 
;----------------------------------------------------------------------------
PE_SectionMove PROC USES EBX hPE:DWORD, lpszSectionName:DWORD, dwSectionIndex:DWORD, lpszSectionNameToMoveTo:DWORD, dwSectionIndexToMoveTo:DWORD
    LOCAL nSectionFrom:DWORD
    LOCAL nSectionTo:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszSectionName != NULL
        
    .ELSE
        mov eax, dwSectionIndex
    .ENDIF
    mov nSectionFrom, eax
    
    .IF lpszSectionNameToMoveTo != NULL
        
    .ELSE
        mov eax, dwSectionIndexToMoveTo
    .ENDIF
    mov nSectionTo, eax    
    
    ; check section indexes are within section count and are not same
    
    ; calc blocks of memory to copy/move
     
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    mov eax, TRUE
    ret
PE_SectionMove ENDP



;############################################################################
;  I M P O R T   S E C T I O N   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; PE_ImportDirectoryTable - Get pointer to ImportDirectoryTable
; Returns: pointer to ImportDirectoryTable or NULL
;----------------------------------------------------------------------------
PE_ImportDirectoryTable PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEImportDirectoryTable
    ret
PE_ImportDirectoryTable ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_ImportLookupTable - Get pointer to Import Lookup Table (array of DWORDs) 
; for the specified ImportDirectoryTable entry (dwImportDirectoryEntryIndex)
; Returns: pointer to Import Lookup Table, or 0
;----------------------------------------------------------------------------
PE_ImportLookupTable PROC USES EBX hPE:DWORD, dwImportDirectoryEntryIndex:DWORD, lpdwImportCount:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pImportDirectoryTable:DWORD
    LOCAL pImportLookupTable:DWORD
    LOCAL bPE64:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PE64
    mov bPE64, eax
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    mov eax, [ebx].PEINFO.PEImportDirectoryCount
    .IF dwImportDirectoryEntryIndex >= eax
        mov eax, 0
        ret
    .ENDIF
    
    Invoke PE_ImportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pImportDirectoryTable, eax

    ; calc specific ImportDirectoryTable entry offset
    mov eax, dwImportDirectoryEntryIndex
    mov ebx, SIZEOF IMAGE_IMPORT_DESCRIPTOR
    mul ebx
    add eax, pImportDirectoryTable
    mov ebx, eax ; offset to specific entry in ebx
    
    mov eax, [ebx].IMAGE_IMPORT_DESCRIPTOR.Characteristics
    Invoke PE_RVAToOffset, hPE, eax
    add eax, PEMemMapPtr ; eax has pointer to Import Lookup Table for this DLL entry
    mov pImportLookupTable, eax

    .IF lpdwImportCount != NULL ; loop and count how many functions exported
        mov eax, 0
        mov ebx, pImportLookupTable
        .IF bPE64 == TRUE
            .WHILE dword ptr [ebx] != 0 && dword ptr [ebx+4] != 0
                inc eax
                add ebx, SIZEOF QWORD ; array of QWORDS each pointing to an IMAGE_IMPORT_BY_NAME structure
            .ENDW
        .ELSE
            .WHILE dword ptr [ebx] != 0
                inc eax
                add ebx, SIZEOF DWORD ; array of DWORDS each pointing to an IMAGE_IMPORT_BY_NAME structure
            .ENDW
        .ENDIF
        mov ebx, lpdwImportCount
        mov [ebx], eax
    .ENDIF
    
    mov eax, pImportLookupTable
    ret
PE_ImportLookupTable ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_ImportHintNameTable - Get pointer to a Hint Name Table for a specific
; function as specified by dwFunctionIndex parameter for a specific DLL 
; (as specified by dwImportDirectoryEntryIndex).
; If import by ordinal then will return will be 0
; Returns: pointer to IMAGE_IMPORT_BY_NAME for specific function or 0
;----------------------------------------------------------------------------
PE_ImportHintNameTable PROC USES EBX hPE:DWORD, dwImportDirectoryEntryIndex:DWORD, dwFunctionIndex:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwImportCount:DWORD
    LOCAL pImportLookupTable:DWORD
    LOCAL pImportLookupTableEntry:DWORD
    LOCAL dwHintNameTableRVA:DWORD
    LOCAL bPE64:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PE64
    mov bPE64, eax
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    
    Invoke PE_ImportLookupTable, hPE, dwImportDirectoryEntryIndex, Addr dwImportCount
    .IF eax == NULL
        ret
    .ENDIF
    mov pImportLookupTable, eax
    
    mov eax, dwFunctionIndex
    .IF eax > dwImportCount
        xor eax, eax
        ret
    .ENDIF
    .IF bPE64 == TRUE
        mov ebx, SIZEOF QWORD
    .ELSE
        mov ebx, SIZEOF DWORD
    .ENDIF
    mul ebx
    add eax, pImportLookupTable
    mov pImportLookupTableEntry, eax
    
    mov ebx, pImportLookupTableEntry
    .IF bPE64 == TRUE
        mov eax, [ebx+4]
    .ELSE
        mov eax, [ebx]
    .ENDIF
    mov dwHintNameTableRVA, eax
    and eax, 80000000h
    .IF eax == 1 ; import by ordinal
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_RVAToOffset, hPE, dwHintNameTableRVA
    .IF eax == 0
        ret
    .ENDIF    
    add eax, PEMemMapPtr
    ; eax points to IMAGE_IMPORT_BY_NAME for this function for this import directory entry
    
    
    ret
PE_ImportHintNameTable ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; 
;----------------------------------------------------------------------------
PE_ImportAddressTable PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    ret
PE_ImportAddressTable ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_ImportDirectoryEntryCount - Get count of ImportDirectoryTable entries
; Returns: count of ImportDirectoryTable entries or 0
;----------------------------------------------------------------------------
PE_ImportDirectoryEntryCount PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEImportDirectoryCount
    ret
PE_ImportDirectoryEntryCount ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_ImportDirectoryEntryFunctions - Get function names for a DLL
; Returns: 
;----------------------------------------------------------------------------
PE_ImportDirectoryEntryFunctions PROC USES EBX hPE:DWORD, dwImportDirectoryEntryIndex:DWORD, lpdwFunctionsList:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwImportCount:DWORD
    LOCAL pImportLookupTable:DWORD
    LOCAL pImportLookupTableEntry:DWORD
    LOCAL dwHintNameTableRVA:DWORD
    LOCAL pNameList:DWORD
    LOCAL pNameListNextFunction:DWORD
    LOCAL dwNameListSize:DWORD
    LOCAL bPE64:DWORD
    LOCAL nImport:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpdwFunctionsList == 0
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PE64
    mov bPE64, eax
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    
    Invoke PE_ImportLookupTable, hPE, dwImportDirectoryEntryIndex, Addr dwImportCount
    .IF eax == NULL
        ret
    .ENDIF
    mov pImportLookupTable, eax
    mov pImportLookupTableEntry, eax
    
    ; calc max name list string size
    mov eax, dwImportCount
    inc eax
    mov ebx, SIZEOF DWORD
    mul ebx
    mov dwNameListSize, eax
    
    Invoke GlobalAlloc, GMEM_FIXED or GMEM_ZEROINIT, dwNameListSize
    .IF eax == NULL
        ret
    .ENDIF
    mov pNameList, eax
    mov pNameListNextFunction, eax

    mov ebx, pImportLookupTableEntry
    mov nImport, 0
    mov eax, 0
    .WHILE eax < dwImportCount
        .IF bPE64 == TRUE
            mov eax, [ebx+4]
        .ELSE
            mov eax, [ebx]
        .ENDIF
        mov dwHintNameTableRVA, eax
        and eax, 80000000h
        .IF eax == 1 ; import by ordinal
            ; do something
        .ENDIF
        
        Invoke PE_RVAToOffset, hPE, dwHintNameTableRVA
        .IF eax == 0
            ret
        .ENDIF    
        add eax, PEMemMapPtr
        mov ebx, eax
        lea eax, [ebx].IMAGE_IMPORT_BY_NAME.Name1
        mov ebx, pNameListNextFunction
        mov [ebx], eax

        add pNameListNextFunction, SIZEOF DWORD
        .IF bPE64 == TRUE
            add pImportLookupTableEntry, SIZEOF QWORD
        .ELSE
            add pImportLookupTableEntry, SIZEOF DWORD
        .ENDIF
        mov ebx, pImportLookupTableEntry
        inc nImport
        mov eax, nImport
    .ENDW
    
    mov ebx, lpdwFunctionsList
    mov eax, pNameList
    mov [ebx], eax
    
    mov eax, dwImportCount
    ret
PE_ImportDirectoryEntryFunctions ENDP



PE_ALIGN
;----------------------------------------------------------------------------
; PE_ImportDirectoryEntryDLL - Get DLL name for specified ImportDirectoryTable 
; Entry (dwImportDirectoryEntryIndex)
; Returns: address of zero terminated DLL name string, or NULL
;----------------------------------------------------------------------------
PE_ImportDirectoryEntryDLL PROC USES EBX hPE:DWORD, dwImportDirectoryEntryIndex:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pImportDirectoryTable:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    mov eax, [ebx].PEINFO.PEImportDirectoryCount
    .IF dwImportDirectoryEntryIndex >= eax
        mov eax, 0
        ret
    .ENDIF
    
    Invoke PE_ImportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov pImportDirectoryTable, eax
    
    ; calc specific ImportDirectoryTable entry offset
    mov eax, dwImportDirectoryEntryIndex
    mov ebx, SIZEOF IMAGE_IMPORT_DESCRIPTOR
    mul ebx
    add eax, pImportDirectoryTable
    mov ebx, eax ; offset to specific entry in ebx
    
    mov eax, [ebx].IMAGE_IMPORT_DESCRIPTOR.Name1
    Invoke PE_RVAToOffset, hPE, eax
    add eax, PEMemMapPtr
    ; eax has pointer to DLL name
    ret
PE_ImportDirectoryEntryDLL ENDP





;############################################################################
;  I N F O   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
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
;----------------------------------------------------------------------------
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

PE_ALIGN
;----------------------------------------------------------------------------
; PE_RichSignatureCompIDs - returns total compids in rich signature
;----------------------------------------------------------------------------
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

PE_ALIGN
;----------------------------------------------------------------------------
; PE_RichSignatureProduct - 
;----------------------------------------------------------------------------
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

PE_ALIGN
;----------------------------------------------------------------------------
; PE_Machine - returns machine id in eax
;----------------------------------------------------------------------------
PE_Machine PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderFile, hPE
    mov ebx, eax
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.Machine
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
    Invoke PE_HeaderFile, hPE
    mov ebx, eax
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.Characteristics
    ret
PE_Characteristics ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_LinkerVersion - returns major and minor linker version in ax 
;----------------------------------------------------------------------------
PE_LinkerVersion PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderOptional, hPE
    mov ebx, eax
    
    Invoke PE_Is64, hPE
    .IF eax == TRUE
        movzx eax, byte ptr [ebx].IMAGE_OPTIONAL_HEADER64.MajorLinkerVersion
        mov ah, al
        movzx ebx, byte ptr [ebx].IMAGE_OPTIONAL_HEADER64.MinorLinkerVersion
        mov al, bl
    .ELSE    
        movzx eax, byte ptr [ebx].IMAGE_OPTIONAL_HEADER32.MajorLinkerVersion
        mov ah, al
        movzx ebx, byte ptr [ebx].IMAGE_OPTIONAL_HEADER32.MinorLinkerVersion
        mov al, bl
    .ENDIF
    ret
PE_LinkerVersion ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_AddressOfEntryPoint - returns OEP in eax
;----------------------------------------------------------------------------
PE_AddressOfEntryPoint PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderOptional, hPE
    mov ebx, eax
    
    Invoke PE_Is64, hPE
    .IF eax == TRUE
        mov eax, [ebx].IMAGE_OPTIONAL_HEADER64.AddressOfEntryPoint
    .ELSE
        mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.AddressOfEntryPoint
    .ENDIF
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
; PE_ImageBase - returns size of image in eax
;----------------------------------------------------------------------------
PE_SizeOfImage PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderOptional, hPE
    mov ebx, eax
    
    Invoke PE_Is64, hPE
    .IF eax == TRUE
        mov eax, [ebx].IMAGE_OPTIONAL_HEADER64.SizeOfImage
    .ELSE
        mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.SizeOfImage
    .ENDIF
    ret
PE_SizeOfImage ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_CheckSum - returns checksum in eax
;----------------------------------------------------------------------------
PE_CheckSum PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderOptional, hPE
    mov ebx, eax
    
    Invoke PE_Is64, hPE
    .IF eax == TRUE
        mov eax, [ebx].IMAGE_OPTIONAL_HEADER64.CheckSum
    .ELSE
        mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.CheckSum
    .ENDIF
    ret
PE_CheckSum ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_Subsystem - returns subsystem id in eax
;----------------------------------------------------------------------------
PE_Subsystem PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    Invoke PE_HeaderOptional, hPE
    mov ebx, eax
    
    Invoke PE_Is64, hPE
    .IF eax == TRUE
        movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER64.Subsystem
    .ELSE
        movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER32.Subsystem
    .ENDIF
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
    Invoke PE_HeaderOptional, hPE
    mov ebx, eax
    
    Invoke PE_Is64, hPE
    .IF eax == TRUE
        movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER64.DllCharacteristics
    .ELSE
        movzx eax, word ptr [ebx].IMAGE_OPTIONAL_HEADER32.DllCharacteristics
    .ENDIF    
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

PE_ALIGN
;----------------------------------------------------------------------------
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
;----------------------------------------------------------------------------
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




;############################################################################
;  E R R O R   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; PE_SetError
;----------------------------------------------------------------------------
PE_SetError PROC USES EBX hPE:DWORD, dwError:DWORD
    .IF hPE != NULL && dwError != PE_ERROR_SUCCESS
        mov ebx, hPE
        mov ebx, [ebx].PEINFO.PEHandle 
        .IF ebx != 0
            mov eax, 0 ; null out hPE handle if it exists
            mov [ebx], eax
        .ENDIF
    .ENDIF
    mov eax, dwError
    mov PELIB_ErrorNo, eax
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
;  H E L P E R   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; PE_RVAToOffset - convert Relative Virtual Address (RVA) to file offset
;----------------------------------------------------------------------------
PE_RVAToOffset PROC USES EBX EDX hPE:DWORD, dwRVA:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nCurrentSection:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwSectionSize:DWORD
    LOCAL dwVirtualAddress:DWORD
    LOCAL dwPointerToRawData:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PESectionCount
    mov nTotalSections, eax
    mov eax, [ebx].PEINFO.PESectionTable
    mov pCurrentSection, eax

    mov ebx, pCurrentSection
    mov edx, dwRVA
    mov eax, 0
    mov nCurrentSection, 0
    .WHILE eax < nTotalSections
        mov eax, [ebx].IMAGE_SECTION_HEADER.Misc.VirtualSize
        .IF eax == 0
            mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
        .ENDIF
        mov dwSectionSize, eax
    
        mov eax, [ebx].IMAGE_SECTION_HEADER.VirtualAddress
        .IF eax <= edx
            mov dwVirtualAddress, eax
            add eax, dwSectionSize
            .IF eax > edx
                mov eax, [ebx].IMAGE_SECTION_HEADER.PointerToRawData
                mov dwPointerToRawData, eax
                
                mov ebx, dwVirtualAddress
                mov eax, edx
                sub eax, ebx
                mov edx, eax
                mov ebx, dwPointerToRawData
                mov eax, edx
                add eax, ebx
                ret
            .ENDIF
        .ENDIF

        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nCurrentSection
        mov eax, nCurrentSection
    .ENDW
    
    mov eax, dwRVA
    ret
PE_RVAToOffset ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; PE_OffsetToRVA - convert file offset to Relative Virtual Address (RVA) 
;----------------------------------------------------------------------------
PE_OffsetToRVA PROC USES EBX hPE:DWORD, dwOffset:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nCurrentSection:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwVirtualAddress:DWORD
    LOCAL dwPointerToRawData:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PESectionCount
    mov nTotalSections, eax
    mov eax, [ebx].PEINFO.PESectionTable
    mov pCurrentSection, eax

    mov ebx, pCurrentSection
    mov edx, dwOffset
    mov eax, 0
    mov nCurrentSection, 0
    .WHILE eax < nTotalSections
        mov eax, [ebx].IMAGE_SECTION_HEADER.PointerToRawData
        .IF eax <= edx
            mov dwPointerToRawData, eax
            mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
            add eax, dwPointerToRawData
            .IF eax > edx
                mov eax, [ebx].IMAGE_SECTION_HEADER.VirtualAddress
                mov dwVirtualAddress, eax
                
                mov ebx, dwPointerToRawData
                mov eax, edx
                sub eax, ebx
                mov edx, eax
                mov ebx, dwVirtualAddress
                mov eax, edx
                add eax, ebx
                ret
            .ENDIF
        .ENDIF

        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nCurrentSection
        mov eax, nCurrentSection
    .ENDW
    
    xor eax, eax
    ret
PE_OffsetToRVA ENDP

PE_ALIGN
;-------------------------------------------------------------------------------------
; PE_FileName - returns in eax pointer to zero terminated string contained filename that is open or NULL if not opened
;-------------------------------------------------------------------------------------
PE_FileName PROC USES EBX hPE:DWORD
    LOCAL PEFilename:DWORD
    .IF hPE == NULL
        mov eax, NULL
        ret
    .ENDIF
    mov ebx, hPE
    lea eax, [ebx].PEINFO.PEFilename
    mov PEFilename, eax
    Invoke lstrlen, PEFilename
    .IF eax == 0
        mov eax, NULL
    .ELSE
        mov eax, PEFilename
    .ENDIF
    ret
PE_FileName endp

PE_ALIGN
;-------------------------------------------------------------------------------------
; PE_FileNameOnly - returns in eax true or false if it managed to pass to the buffer pointed at lpszFileNameOnly, the stripped filename without extension
;-------------------------------------------------------------------------------------
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

PE_ALIGN
;-------------------------------------------------------------------------------------
; PE_FileSize - returns in eax size of file or 0
;-------------------------------------------------------------------------------------
PE_FileSize PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFilesize
    ret
PE_FileSize endp

PE_ALIGN
;-------------------------------------------------------------------------------------
; PE_FileOffset - returns file offset from mapped address
;-------------------------------------------------------------------------------------
PE_FileOffset PROC USES EBX hPE:DWORD, dwMappedAddress:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    sub eax, dwMappedAddress
    ret
PE_FileOffset ENDP






;############################################################################
;  I N T E R N A L   F U N C T I O N S
;############################################################################

PE_ALIGN
;----------------------------------------------------------------------------
; Checks the PE signatures to determine if they are valid
;----------------------------------------------------------------------------
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

PE_ALIGN
;----------------------------------------------------------------------------
; Strip path name to just filename Without extention
;----------------------------------------------------------------------------
PEJustFname PROC szFilePathName:DWORD, szFileName:DWORD
    LOCAL LenFilePathName:DWORD
    LOCAL nPosition:DWORD
    
    Invoke lstrlen, szFilePathName
    mov LenFilePathName, eax
    mov nPosition, eax
    
    .IF LenFilePathName == 0
        mov byte ptr [edi], 0
        ret
    .ENDIF
    
    mov esi, szFilePathName
    add esi, eax
    
    mov eax, nPosition
    .WHILE eax != 0
        movzx eax, byte ptr [esi]
        .IF al == '\' || al == ':' || al == '/'
            inc esi
            .BREAK
        .ENDIF
        dec esi
        dec nPosition
        mov eax, nPosition
    .ENDW
    mov edi, szFileName
    mov eax, nPosition
    .WHILE eax != LenFilePathName
        movzx eax, byte ptr [esi]
        .IF al == '.' ; stop here
            .BREAK
        .ENDIF
        mov byte ptr [edi], al
        inc edi
        inc esi
        inc nPosition
        mov eax, nPosition
    .ENDW
    mov byte ptr [edi], 0h
    ret
PEJustFname ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; Increase (resize) PE file. Adjustments to pointers and other data to be handled by 
; other functions.
; Returns: TRUE on success or FALSE otherwise. 
;----------------------------------------------------------------------------
PEIncreaseFileSize PROC USES EBX hPE:DWORD, dwNewSize:DWORD
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
    .IF dwNewSize <= eax ; if size is less than existing file's size
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
    ; Create file mapping of new size
    ;---------------------------------------------------
    mov eax, dwNewSize
    mov PENewFileSize, eax
    .IF bReadOnly == TRUE
        Invoke CreateFileMapping, hPEFile, NULL, PAGE_READONLY, 0, dwNewSize, NULL ; Create memory mapped file
    .ELSE
        Invoke CreateFileMapping, hPEFile, NULL, PAGE_READWRITE, 0, dwNewSize, NULL ; Create memory mapped file
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
    ; Close existing mapping and only use new one now
    ;---------------------------------------------------
    Invoke UnmapViewOfFile, PEMemMapPtr
    Invoke CloseHandle, PEMemMapHandle
    
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
PEIncreaseFileSize ENDP

PE_ALIGN
;----------------------------------------------------------------------------
; Decrease (resize) PE file. Adjustments to pointers and other data to be handled by 
; other functions. Move data before calling this.
; Returns: TRUE on success or FALSE otherwise. 
;----------------------------------------------------------------------------
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



;------------------------------------------------------------------------------
; PEDwordToAscii - Paul Dixon's utoa_ex function. unsigned dword to ascii.
; Returns: Buffer pointed to by lpszAsciiString will contain ascii string
;------------------------------------------------------------------------------
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
PEDwordToAscii PROC dwValue:DWORD, lpszAsciiString:DWORD
    mov eax, [esp+4]                ; uvar      : unsigned variable to convert
    mov ecx, [esp+8]                ; pbuffer   : pointer to result buffer

    push esi
    push edi

    jmp udword

  align 4
  chartab:
    dd "00","10","20","30","40","50","60","70","80","90"
    dd "01","11","21","31","41","51","61","71","81","91"
    dd "02","12","22","32","42","52","62","72","82","92"
    dd "03","13","23","33","43","53","63","73","83","93"
    dd "04","14","24","34","44","54","64","74","84","94"
    dd "05","15","25","35","45","55","65","75","85","95"
    dd "06","16","26","36","46","56","66","76","86","96"
    dd "07","17","27","37","47","57","67","77","87","97"
    dd "08","18","28","38","48","58","68","78","88","98"
    dd "09","19","29","39","49","59","69","79","89","99"

  udword:
    mov esi, ecx                    ; get pointer to answer
    mov edi, eax                    ; save a copy of the number

    mov edx, 0D1B71759h             ; =2^45\10000    13 bit extra shift
    mul edx                         ; gives 6 high digits in edx

    mov eax, 68DB9h                 ; =2^32\10000+1

    shr edx, 13                     ; correct for multiplier offset used to give better accuracy
    jz short skiphighdigits         ; if zero then don't need to process the top 6 digits

    mov ecx, edx                    ; get a copy of high digits
    imul ecx, 10000                 ; scale up high digits
    sub edi, ecx                    ; subtract high digits from original. EDI now = lower 4 digits

    mul edx                         ; get first 2 digits in edx
    mov ecx, 100                    ; load ready for later

    jnc short next1                 ; if zero, supress them by ignoring
    cmp edx, 9                      ; 1 digit or 2?
    ja   ZeroSupressed              ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    inc esi                         ; update pointer by 1
    jmp  ZS1                        ; continue with pairs of digits to the end

  align 16
  next1:
    mul ecx                         ; get next 2 digits
    jnc short next2                 ; if zero, supress them by ignoring
    cmp edx, 9                      ; 1 digit or 2?
    ja   ZS1a                       ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    add esi, 1                      ; update pointer by 1
    jmp  ZS2                        ; continue with pairs of digits to the end

  align 16
  next2:
    mul ecx                         ; get next 2 digits
    jnc short next3                 ; if zero, supress them by ignoring
    cmp edx, 9                      ; 1 digit or 2?
    ja   ZS2a                       ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    add esi, 1                      ; update pointer by 1
    jmp  ZS3                        ; continue with pairs of digits to the end

  align 16
  next3:

  skiphighdigits:
    mov eax, edi                    ; get lower 4 digits
    mov ecx, 100

    mov edx, 28F5C29h               ; 2^32\100 +1
    mul edx
    jnc short next4                 ; if zero, supress them by ignoring
    cmp edx, 9                      ; 1 digit or 2?
    ja  short ZS3a                  ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    inc esi                         ; update pointer by 1
    jmp short  ZS4                  ; continue with pairs of digits to the end

  align 16
  next4:
    mul ecx                         ; this is the last pair so don; t supress a single zero
    cmp edx, 9                      ; 1 digit or 2?
    ja  short ZS4a                  ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    mov byte ptr [esi+1], 0         ; zero terminate string

    pop edi
    pop esi
    ret 8

  align 16
  ZeroSupressed:
    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dx
    add esi, 2                      ; write them to answer

  ZS1:
    mul ecx                         ; get next 2 digits
  ZS1a:
    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dx                   ; write them to answer
    add esi, 2

  ZS2:
    mul ecx                         ; get next 2 digits
  ZS2a:
    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dx                   ; write them to answer
    add esi, 2

  ZS3:
    mov eax, edi                    ; get lower 4 digits
    mov edx, 28F5C29h               ; 2^32\100 +1
    mul edx                         ; edx= top pair
  ZS3a:
    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dx                   ; write to answer
    add esi, 2                      ; update pointer

  ZS4:
    mul ecx                         ; get final 2 digits
  ZS4a:
    mov edx, chartab[edx*4]         ; look them up
    mov [esi], dx                   ; write to answer

    mov byte ptr [esi+2], 0         ; zero terminate string

  sdwordend:

    pop edi
    pop esi
    ret 8
PEDwordToAscii ENDP
OPTION PROLOGUE:PrologueDef
OPTION EPILOGUE:EpilogueDef


END






















