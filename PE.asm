;==============================================================================
;
; PE LIBRARY
;
; Copyright (c) 2019 by fearless
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

;------------------------------------------------------------------------------
; Prototypes for internal use
;------------------------------------------------------------------------------
PESignature             PROTO :DWORD
PEJustFname             PROTO :DWORD, :DWORD

PEIncreaseFileSize      PROTO :DWORD, :DWORD
PEDecreaseFileSize      PROTO :DWORD, :DWORD
PEDwordToAscii          PROTO :DWORD, :DWORD
PE_SetError             PROTO :DWORD, :DWORD

PUBLIC PELIB_ErrorNo



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
        ; http://archive.is/w01DO#selection-265.0-265.44
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





PE_LIBEND






















