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

;------------------------------------------------------------------------------
; PE Prototypes
;------------------------------------------------------------------------------
PE_OpenFile                 PROTO :DWORD,:DWORD,:DWORD              ; lpszPEFilename, bReadOnly, lpdwPEHandle. Returns in eax a handle used in other functions: hPE
PE_CloseFile                PROTO :DWORD                            ; hPE returned from PE_OpenFile.
PE_Analyze                  PROTO :DWORD,:DWORD                     ; pPEInMemory, lpdwPEHandle. Returns in eax a handle used in other functions: hPE
PE_Finish                   PROTO :DWORD                            ; hPE returned from PE_Analyze.
PE_GetError                 PROTO                                   ;

; Header Pointer Functions:
PE_HeaderDOS                PROTO :DWORD                            ; hPE
PE_HeaderNT                 PROTO :DWORD                            ; hPE
PE_HeaderFile               PROTO :DWORD                            ; hPE
PE_HeaderOptional           PROTO :DWORD                            ; hPE
PE_HeaderSections           PROTO :DWORD                            ; hPE
PE_HeaderRich               PROTO :DWORD                            ; hPE
PE_HeaderStub               PROTO :DWORD                            ; hPE

; Section Functions:
PE_SectionHeaderCount       PROTO :DWORD                            ; hPE
PE_SectionsHeaders          PROTO :DWORD                            ; hPE
PE_SectionHeaderByIndex     PROTO :DWORD,:DWORD                     ; hPE, dwSectionIndex
PE_SectionHeaderByName      PROTO :DWORD,:DWORD                     ; hPE, lpszSectionName
PE_SectionHeaderByType      PROTO :DWORD,:DWORD                     ; hPE, dwSectionType
PE_SectionHeaderByAddr      PROTO :DWORD,:DWORD                     ; hPE, dwAddress
PE_SectionName              PROTO :DWORD,:DWORD                     ; hPE, dwSectionIndex
PE_SectionCharacteristics   PROTO :DWORD,:DWORD                     ; hPE, dwSectionIndex
PE_SectionType              PROTO :DWORD,:DWORD                     ; hPE, dwSectionIndex

; Section Manipulate Functions: (WIP - NOT FINISHED - DONT USE)
PE_SectionAdd               PROTO :DWORD,:DWORD,:DWORD,:DWORD       ; hPE, lpszSectionName, dwSectionSize, dwSectionCharacteristics
PE_SectionDelete            PROTO :DWORD,:DWORD,:DWORD              ; hPE, lpszSectionName, dwSectionIndex
PE_SectionInsert            PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD; hPE, lpszSectionName, dwSectionSize, dwSectionCharacteristics, dwSectionIndex
PE_SectionMove              PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD; hPE, lpszSectionName, dwSectionIndex, lpszSectionNameToMoveTo, dwSectionIndexToMoveTo

; Import Functions
PE_ImportDirectoryTable     PROTO :DWORD                            ; hPE
PE_ImportLookupTable        PROTO :DWORD,:DWORD,:DWORD              ; hPE, dwImportDirectoryEntryIndex, lpdwImportCount
PE_ImportHintNameTable      PROTO :DWORD,:DWORD,:DWORD              ; hPE, dwImportDirectoryEntryIndex, dwFunctionIndex
PE_ImportAddressTable       PROTO :DWORD                            ; hPE
PE_ImportDirectoryEntryCount PROTO :DWORD                           ; hPE
PE_ImportDirectoryEntryDLL  PROTO :DWORD,:DWORD                     ; hPE, dwImportDirectoryEntryIndex
PE_ImportDirectoryEntryFunctions PROTO :DWORD,:DWORD,:DWORD         ; hPE, dwImportDirectoryEntryIndex, lpdwFunctionsList

; Common Info Functions
;------------------------------------------------------------------------------
; Note: Only some functions are provided for reading commonly accessed fields
; in various PE structures. Others can be read by obtaining the pointer to the
; relevant PE structure and reading the required field(s) directly.
;------------------------------------------------------------------------------

PE_RichSignatureDecode      PROTO :DWORD,:DWORD,:DWORD              ; hPE, lpdwDecodedRichSignature, lpdwSize
PE_Machine                  PROTO :DWORD                            ; hPE
PE_Characteristics          PROTO :DWORD                            ; hPE
PE_LinkerVersion            PROTO :DWORD                            ; hPE
PE_AddressOfEntryPoint      PROTO :DWORD                            ; hPE
PE_ImageBase                PROTO :DWORD                            ; hPE
PE_SizeOfImage              PROTO :DWORD                            ; hPE
PE_CheckSum                 PROTO :DWORD                            ; hPE
PE_Subsystem                PROTO :DWORD                            ; hPE
PE_DllCharacteristics       PROTO :DWORD                            ; hPE
PE_IsDll                    PROTO :DWORD                            ; hPE
PE_Is64                     PROTO :DWORD                            ; hPE
PE_Hash                     PROTO :DWORD,:DWORD,:DWORD,:DWORD       ; hPE, dwHashType, lpHashBytes, lpdwHashSize

; Helper Functions:
PE_RVAToOffset              PROTO :DWORD,:DWORD                     ; hPE, dwRVA
PE_OffsetToRVA              PROTO :DWORD,:DWORD                     ; hPE, dwOffset

PE_FileName                 PROTO :DWORD                            ; hPE
PE_FileNameOnly             PROTO :DWORD,:DWORD                     ; hPE, lpszFileNameOnly
PE_FileSize                 PROTO :DWORD                            ; hPE


;------------------------------------------------------------------------------
; PE Structures
;------------------------------------------------------------------------------
IFNDEF RICH_SIGNATURE_ENTRY
RICH_SIGNATURE_ENTRY  STRUC
    UNION
        STRUCT
            EntryType DW ?
            Build     DW ?
        ENDS
        ID            DD ?
    ENDS
    Count             DD ?
; Entries start at offset 16 from Rich Signature Header 
; After 'DanS' +12    
RICH_SIGNATURE_ENTRY  ENDS
ENDIF

IFNDEF IMPORT_FUNCTION
IMPORT_FUNCTION          STRUC; Combines Import Lookup Table & Hint/Name Table for a function
    dwOrdinalNameFlag    DD ? ; TRUE for ordinal, FALSE for name
    lpszFunctionName     DD ? ; pointer to function name string in PE memory mapped file
    dwFunctionNameOffset DD ? ; file offset to function name string 
    dwFunctionNameRVA    DD ? ; RVA to function name string
    dwOrdinal            DD ? ; Ordinal number
    dwHint               DD ? ; Hint number
IMPORT_FUNCTION          ENDS
ENDIF

IFNDEF IMAGE_DATA_DIRECTORY
IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress   DWORD ?
    isize            DWORD ?
IMAGE_DATA_DIRECTORY ENDS
ENDIF

IFNDEF IMAGE_SECTION_HEADER
IMAGE_SECTION_HEADER     STRUCT
    Name1 DB IMAGE_SIZEOF_SHORT_NAME dup(?)
    union Misc
        PhysicalAddress  DWORD ?
        VirtualSize      DWORD ?
    ends
    VirtualAddress       DWORD ?
    SizeOfRawData        DWORD ?
    PointerToRawData     DWORD ?
    PointerToRelocations DWORD ?
    PointerToLinenumbers DWORD ?
    NumberOfRelocations  WORD  ?
    NumberOfLinenumbers  WORD  ?
    Characteristics      DWORD ?
IMAGE_SECTION_HEADER     ENDS
ENDIF

IFNDEF IMAGE_OPTIONAL_HEADER32
IMAGE_OPTIONAL_HEADER32         STRUCT
    Magic                       WORD  ?
    MajorLinkerVersion          BYTE  ?
    MinorLinkerVersion          BYTE  ?
    SizeOfCode                  DWORD ?
    SizeOfInitializedData       DWORD ?
    SizeOfUninitializedData     DWORD ?
    AddressOfEntryPoint         DWORD ?
    BaseOfCode                  DWORD ?
    BaseOfData                  DWORD ?
    ImageBase                   DWORD ?
    SectionAlignment            DWORD ?
    FileAlignment               DWORD ?
    MajorOperatingSystemVersion WORD  ?
    MinorOperatingSystemVersion WORD  ?
    MajorImageVersion           WORD  ?
    MinorImageVersion           WORD  ?
    MajorSubsystemVersion       WORD  ?
    MinorSubsystemVersion       WORD  ?
    Win32VersionValue           DWORD ?
    SizeOfImage                 DWORD ?
    SizeOfHeaders               DWORD ?
    CheckSum                    DWORD ?
    Subsystem                   WORD  ?
    DllCharacteristics          WORD  ?
    SizeOfStackReserve          DWORD ?
    SizeOfStackCommit           DWORD ?
    SizeOfHeapReserve           DWORD ?
    SizeOfHeapCommit            DWORD ?
    LoaderFlags                 DWORD ?
    NumberOfRvaAndSizes         DWORD ?
    DataDirectory               IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup(<>)
IMAGE_OPTIONAL_HEADER32         ENDS
ENDIF

IFNDEF IMAGE_OPTIONAL_HEADER64
IMAGE_OPTIONAL_HEADER64         STRUCT
    Magic                       WORD  ?
    MajorLinkerVersion          BYTE  ?
    MinorLinkerVersion          BYTE  ?
    SizeOfCode                  DWORD ?
    SizeOfInitializedData       DWORD ?
    SizeOfUninitializedData     DWORD ?
    AddressOfEntryPoint         DWORD ?
    BaseOfCode                  DWORD ?
    ImageBase                   QWORD ?
    SectionAlignment            DWORD ?
    FileAlignment               DWORD ?
    MajorOperatingSystemVersion WORD  ?
    MinorOperatingSystemVersion WORD  ?
    MajorImageVersion           WORD  ?
    MinorImageVersion           WORD  ?
    MajorSubsystemVersion       WORD  ?
    MinorSubsystemVersion       WORD  ?
    Win32VersionValue           DWORD ?
    SizeOfImage                 DWORD ?
    SizeOfHeaders               DWORD ?
    CheckSum                    DWORD ?
    Subsystem                   WORD  ?
    DllCharacteristics          WORD  ?
    SizeOfStackReserve          QWORD ?
    SizeOfStackCommit           QWORD ?
    SizeOfHeapReserve           QWORD ?
    SizeOfHeapCommit            QWORD ?
    LoaderFlags                 DWORD ?
    NumberOfRvaAndSizes         DWORD ?
    DataDirectory               IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup(<>)
IMAGE_OPTIONAL_HEADER64         ENDS
ENDIF

IMAGE_OPTIONAL_HEADER  equ  <IMAGE_OPTIONAL_HEADER32>

IFNDEF IMAGE_FILE_HEADER
IMAGE_FILE_HEADER        STRUCT
    Machine              WORD  ?
    NumberOfSections     WORD  ?
    TimeDateStamp        DWORD ?
    PointerToSymbolTable DWORD ?
    NumberOfSymbols      DWORD ?
    SizeOfOptionalHeader WORD  ?
    Characteristics      WORD  ?
IMAGE_FILE_HEADER        ENDS
ENDIF

IFNDEF IMAGE_NT_HEADERS
IMAGE_NT_HEADERS   STRUCT
    Signature      DWORD                   ?
    FileHeader     IMAGE_FILE_HEADER       <>
    OptionalHeader IMAGE_OPTIONAL_HEADER32 <>
IMAGE_NT_HEADERS   ENDS
ENDIF

IFNDEF IMAGE_NT_HEADERS32
IMAGE_NT_HEADERS32 STRUCT
    Signature      DWORD                   ?
    FileHeader     IMAGE_FILE_HEADER       <>
    OptionalHeader IMAGE_OPTIONAL_HEADER32 <>
IMAGE_NT_HEADERS32 ENDS
ENDIF

IFNDEF IMAGE_NT_HEADERS64
IMAGE_NT_HEADERS64 STRUCT
    Signature      DWORD                   ?
    FileHeader     IMAGE_FILE_HEADER       <>
    OptionalHeader IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS
ENDIF

IFNDEF IMAGE_EXPORT_DIRECTORY
IMAGE_EXPORT_DIRECTORY    STRUCT
    Characteristics       DWORD ?
    TimeDateStamp         DWORD ?
    MajorVersion          WORD  ?
    MinorVersion          WORD  ?
    nName                 DWORD ?
    nBase                 DWORD ?
    NumberOfFunctions     DWORD ?
    NumberOfNames         DWORD ?
    AddressOfFunctions    DWORD ?
    AddressOfNames        DWORD ?
    AddressOfNameOrdinals DWORD ?
IMAGE_EXPORT_DIRECTORY    ENDS
ENDIF

IFNDEF IMAGE_IMPORT_DESCRIPTOR
IMAGE_IMPORT_DESCRIPTOR     STRUCT
    union
        Characteristics     DWORD ?
        OriginalFirstThunk  DWORD ?
    ends
    TimeDateStamp           DWORD ?
    ForwarderChain          DWORD ?
    Name1                   DWORD ?
    FirstThunk              DWORD ?
IMAGE_IMPORT_DESCRIPTOR     ENDS
ENDIF

IFNDEF IMAGE_BASE_RELOCATION
IMAGE_BASE_RELOCATION STRUCT
    VirtualAddress dd   ?
    SizeOfBlock dd      ?
IMAGE_BASE_RELOCATION ENDS
ENDIF

IFNDEF IMAGE_IMPORT_BY_NAME
IMAGE_IMPORT_BY_NAME STRUCT
    Hint dw     ?
    Name1 db    ?
IMAGE_IMPORT_BY_NAME ENDS
ENDIF

IFNDEF IMAGE_RESOURCE_DIRECTORY
IMAGE_RESOURCE_DIRECTORY STRUCT
    Characteristics dd      ?
    TimeDateStamp dd        ?
    MajorVersion dw         ?
    MinorVersion dw         ?
    NumberOfNamedEntries dw ?
    NumberOfIdEntries dw    ?
IMAGE_RESOURCE_DIRECTORY ENDS
ENDIF

IFNDEF IMAGE_RESOURCE_DIRECTORY_ENTRY
IMAGE_RESOURCE_DIRECTORY_ENTRY STRUCT
    union
        rName   RECORD NameIsString:1,NameOffset:31
        Name1 dd ?
        Id dw ?
    ends
    union
        OffsetToData dd ?
          rDirectory    RECORD DataIsDirectory:1,OffsetToDirectory:31
    ends
IMAGE_RESOURCE_DIRECTORY_ENTRY ENDS
ENDIF

IFNDEF IMAGE_RESOURCE_DIRECTORY_STRING
IMAGE_RESOURCE_DIRECTORY_STRING STRUCT
    Length1 dw      ?
    NameString db   ?
IMAGE_RESOURCE_DIRECTORY_STRING ENDS
ENDIF

IFNDEF IMAGE_RESOURCE_DIR_STRING_U
IMAGE_RESOURCE_DIR_STRING_U STRUCT
    Length1 dw      ?
    NameString dw   ?
IMAGE_RESOURCE_DIR_STRING_U ENDS
ENDIF

IFNDEF IMAGE_RESOURCE_DATA_ENTRY
IMAGE_RESOURCE_DATA_ENTRY STRUCT
    OffsetToData dd ?
    Size1 dd        ?
    CodePage dd     ?
    Reserved dd     ?
IMAGE_RESOURCE_DATA_ENTRY ENDS
ENDIF

IFNDEF IMAGE_DOS_HEADER
IMAGE_DOS_HEADER STRUCT
    e_magic      WORD ?
    e_cblp       WORD ?
    e_cp         WORD ?
    e_crlc       WORD ?
    e_cparhdr    WORD ?
    e_minalloc   WORD ?
    e_maxalloc   WORD ?
    e_ss         WORD ?
    e_sp         WORD ?
    e_csum       WORD ?
    e_ip         WORD ?
    e_cs         WORD ?
    e_lfarlc     WORD ?
    e_ovno       WORD ?
    e_res        WORD 4 dup(?)
    e_oemid      WORD ?
    e_oeminfo    WORD ?
    e_res2       WORD 10 dup(?)
    e_lfanew     DWORD ?
IMAGE_DOS_HEADER ENDS
ENDIF

.CONST
;------------------------------------------------------------------------------
; PE Constants
;------------------------------------------------------------------------------
PE_ALIGN                        TEXTEQU <ALIGN 16>
PE_INVALID                      EQU 0
PE_ARCH_32                      EQU 1
PE_ARCH_64                      EQU 2
PE32                            EQU PE_ARCH_32
PE64                            EQU PE_ARCH_64

; PE Error Enums:
PE_ERROR_SECTION_MOVE           EQU -14 ; Failed to move section
PE_ERROR_SECTION_INS            EQU -13 ; Failed to add and insert section to PE file
PE_ERROR_SECTION_DEL            EQU -12 ; Failed to delete section to PE file
PE_ERROR_SECTION_ADD            EQU -11 ; Failed to add section to PE file
PE_ERROR_ANALYZE_NULL           EQU -10 ; PE memory address is 0 or size is 0
PE_ERROR_ANALYZE_INVALID        EQU  -9 ; Invalid magic no or signature 
PE_ERROR_ANALYZE_ALLOC          EQU  -8 ; Could not allocate memory for initial analysis
PE_ERROR_OPEN_VIEW              EQU  -7 ; Could not map a view of PE file
PE_ERROR_OPEN_MAP               EQU  -6 ; Could not map PE file
PE_ERROR_OPEN_SIZE_HIGH         EQU  -5 ; File size too large to be a valid PE file
PE_ERROR_OPEN_SIZE_LOW          EQU  -4 ; File size too low to be a valid PE file
PE_ERROR_OPEN_FILE              EQU  -3 ; Error opening PE file
PE_ERROR_OPEN_INVALID           EQU  -2 ; Not a valid PE file 
PE_ERROR_NO_HANDLE              EQU  -1 ; No variable provided to store hPE in or hPE is null
PE_ERROR_SUCCESS                EQU   0 ; Success

; dwSectionType for PE_SectionHeaderByType:
SEC_BSS                         EQU  0 ; .bss - Uninitialized data (free format)
SEC_CORMETA                     EQU  1 ; .cormeta - CLR metadata that indicates that the object file contains managed code
SEC_DATA                        EQU  2 ; .data - Initialized data (free format) 
SEC_DEBUG                       EQU  3 ; .debug - Debug information
SEC_DRECTVE                     EQU  4 ; .drectve - Linker options 
SEC_EDATA                       EQU  5 ; .edata - export tables
SEC_IDATA                       EQU  6 ; .idata - import tables
SEC_IDLSYM                      EQU  7 ; .idlsym - Includes registered SEH (image only) to support IDL attributes.
SEC_PDATA                       EQU  8 ; .pdata - Exception information
SEC_RDATA                       EQU  9 ; .rdata - Read-only initialized data
SEC_RELOC                       EQU 10 ; .reloc - Image relocations 
SEC_RSRC                        EQU 11 ; .rsrc - Resource directory
SEC_SBSS                        EQU 12 ; .sbss - GP-relative uninitialized data (free format)
SEC_SDATA                       EQU 13 ; .sdata - GP-relative initialized data (free format
SEC_SRDATA                      EQU 14 ; .srdata - GP-relative read-only data (free format)
SEC_SXDATA                      EQU 15 ; .sxdata - Registered exception handler data (free format and x86/object only)
SEC_TEXT                        EQU 16 ; .text - Executable code (free format)
SEC_TLS                         EQU 17 ; .tls - Thread-local storage (object only)
SEC_VSDATA                      EQU 18 ; .vsdata - GP-relative initialized data (free format and for ARM, SH4, and Thumb architectures only)
SEC_XDATA                       EQU 19 ; .xdata - Exception information (free format)
SEC_LAST                        EQU SEC_XDATA
SEC_CODE                        EQU SEC_TEXT
SEC_EXPORT                      EQU SEC_EDATA
SEC_IMPORT                      EQU SEC_IDATA
SEC_RESOURCE                    EQU SEC_RSRC
SEC_EXCEPTION                   EQU SEC_PDATA
SEC_DOTNET                      EQU SEC_CORMETA

; Signatures:
MZ_SIGNATURE                    EQU 5A4Dh ; ZM - 'MZ'
PE_SIGNATURE                    EQU 4550h ; EP - 'PE'
NE_SIGNATURE                    EQU 4E50h ; EN - 'NE'

; PE Magic Number:
IMAGE_NT_OPTIONAL_HDR32_MAGIC   EQU 010Bh ; The file is an executable image.
IMAGE_NT_OPTIONAL_HDR64_MAGIC   EQU 020Bh ; The file is an executable image.
IMAGE_ROM_OPTIONAL_HDR_MAGIC    EQU 0107h ; The file is a ROM image.

; Optional Header Structure Sizes:
SIZEOF_STANDARD_FIELDS_PE32     EQU 28d
SIZEOF_STANDARD_FIELDS_PE64     EQU 24d
SIZEOF_WINDOWS_FIELDS_PE32      EQU 68d
SIZEOF_WINDOWS_FIELDS_PE64      EQU 88d

;------------------------------------------------------------------------------
; MS-COFF defines:
;------------------------------------------------------------------------------

; Machine Types:
IMAGE_FILE_MACHINE_UNKNOWN      EQU 0000h ; The contents of this field are assumed to be applicable to any machine type
IMAGE_FILE_MACHINE_AM33EQU      EQU 01D3h ; Matsushita AM33
IMAGE_FILE_MACHINE_AMD64        EQU 8664h ; x64
IMAGE_FILE_MACHINE_ARM          EQU 01C0h ; ARM little endian
IMAGE_FILE_MACHINE_ARM64        EQU 0AA64h; ARM64 little endian
IMAGE_FILE_MACHINE_ARMNT        EQU 01C4h ; ARM Thumb-2 little endian
IMAGE_FILE_MACHINE_EBC          EQU 0EBCh ; EFI byte code
IMAGE_FILE_MACHINE_I386         EQU 014Ch ; Intel 386 or later processors and compatible processors
IMAGE_FILE_MACHINE_IA64         EQU 0200h ; Intel Itanium processor family
IMAGE_FILE_MACHINE_M32R         EQU 9041h ; Mitsubishi M32R little endian
IMAGE_FILE_MACHINE_MIPS16       EQU 0266h ; MIPS16
IMAGE_FILE_MACHINE_MIPSFPU      EQU 0366h ; MIPS with FPU
IMAGE_FILE_MACHINE_MIPSFPU16    EQU 0466h ; MIPS16 with FPU
IMAGE_FILE_MACHINE_POWERPC      EQU 01F0h ; Power PC little endian
IMAGE_FILE_MACHINE_POWERPCFP    EQU 01F1h ; Power PC with floating point support
IMAGE_FILE_MACHINE_R4000        EQU 0166h ; MIPS little endian
IMAGE_FILE_MACHINE_RISCV32      EQU 5032h ; RISC-V 32-bit address space
IMAGE_FILE_MACHINE_RISCV64      EQU 5064h ; RISC-V 64-bit address space
IMAGE_FILE_MACHINE_RISCV128     EQU 5128h ; RISC-V 128-bit address space
IMAGE_FILE_MACHINE_SH3          EQU 01A2h ; Hitachi SH3
IMAGE_FILE_MACHINE_SH3DSP       EQU 01A3h ; Hitachi SH3 DSP
IMAGE_FILE_MACHINE_SH4          EQU 01A6h ; Hitachi SH4
IMAGE_FILE_MACHINE_SH5          EQU 01A8h ; Hitachi SH5
IMAGE_FILE_MACHINE_THUMB        EQU 01C2h ; Thumb
IMAGE_FILE_MACHINE_WCEMIPSV2    EQU 0169h ; MIPS little-endian WCE v2 

; Characteristics:
IMAGE_FILE_RELOCS_STRIPPED         EQU 0001h ; Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address.
IMAGE_FILE_EXECUTABLE_IMAGE        EQU 0002h ; Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
IMAGE_FILE_LINE_NUMS_STRIPPED      EQU 0004h ; COFF line numbers have been removed. This flag is deprecated and should be zero.
IMAGE_FILE_LOCAL_SYMS_STRIPPED     EQU 0008h ; COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
IMAGE_FILE_AGGRESSIVE_WS_TRIM      EQU 0010h ; Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
IMAGE_FILE_LARGE_ADDRESS_AWARE     EQU 0020h ; Application can handle > 2-GB addresses.
IMAGE_FILE_RESERVED_FUTURE_USE     EQU 0040h ; This flag is reserved for future use.
IMAGE_FILE_BYTES_REVERSED_LO       EQU 0080h ; Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
IMAGE_FILE_32BIT_MACHINE           EQU 0100h ; Machine is based on a 32-bit-word architecture.
IMAGE_FILE_DEBUG_STRIPPED          EQU 0200h ; Debugging information is removed from the image file.
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP EQU 0400h ; If the image is on removable media, fully load it and copy it to the swap file.
IMAGE_FILE_NET_RUN_FROM_SWAP       EQU 0800h ; If the image is on network media, fully load it and copy it to the swap file.
IMAGE_FILE_SYSTEM                  EQU 1000h ; The image file is a system file, not a user program.
IMAGE_FILE_DLL                     EQU 2000h ; The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
IMAGE_FILE_UP_SYSTEM_ONLY          EQU 4000h ; The file should be run only on a uniprocessor machine.
IMAGE_FILE_BYTES_REVERSED_HI       EQU 8000h ; Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero. 

; Windows Subsystem:
IMAGE_SUBSYSTEM_UNKNOWN                  EQU  0 ; An unknown subsystem
IMAGE_SUBSYSTEM_NATIVE                   EQU  1 ; Device drivers and native Windows processes
IMAGE_SUBSYSTEM_WINDOWS_GUI              EQU  2 ; The Windows graphical user interface (GUI) subsystem
IMAGE_SUBSYSTEM_WINDOWS_CUI              EQU  3 ; The Windows character subsystem
IMAGE_SUBSYSTEM_OS2_CUI                  EQU  5 ; The OS/2 character subsystem
IMAGE_SUBSYSTEM_POSIX_CUI                EQU  7 ; The Posix character subsystem
IMAGE_SUBSYSTEM_NATIVE_WINDOWS           EQU  8 ; Native Win9x driver
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           EQU  9 ; Windows CE
IMAGE_SUBSYSTEM_EFI_APPLICATION          EQU 10 ; An Extensible Firmware Interface (EFI) application
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  EQU 11 ; An EFI driver with boot services
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       EQU 12 ; An EFI driver with run-time services
IMAGE_SUBSYSTEM_EFI_ROM                  EQU 13 ; An EFI ROM image
IMAGE_SUBSYSTEM_XBOX                     EQU 14 ; XBOX
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION EQU 16 ; Windows boot application. 

; DLL Characteristics: 
IMAGE_DLLCHARACTERISTICS_RESERVED1             EQU 0001h ; Reserved, must be zero.
IMAGE_DLLCHARACTERISTICS_RESERVED2             EQU 0002h ; Reserved, must be zero.
IMAGE_DLLCHARACTERISTICS_RESERVED3             EQU 0004h ; Reserved, must be zero.
IMAGE_DLLCHARACTERISTICS_RESERVED4             EQU 0008h ; Reserved, must be zero.
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       EQU 0020h ; Image can handle a high entropy 64-bit virtual address space.
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          EQU 0040h ; DLL can be relocated at load time.
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       EQU 0080h ; Code Integrity checks are enforced.
IMAGE_DLLCHARACTERISTICS_NX_COMPAT             EQU 0100h ; Image is NX compatible.
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          EQU 0200h ; Isolation aware, but do not isolate the image.
IMAGE_DLLCHARACTERISTICS_NO_SEH                EQU 0400h ; Does not use structured exception (SE) handling. No SE handler may be called in this image.
IMAGE_DLLCHARACTERISTICS_NO_BIND               EQU 0800h ; Do not bind the image.
IMAGE_DLLCHARACTERISTICS_APPCONTAINER          EQU 1000h ; Image must execute in an AppContainer.
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            EQU 2000h ; A WDM driver.
IMAGE_DLLCHARACTERISTICS_GUARD_CF              EQU 4000h ; Image supports Control Flow Guard.
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE EQU 8000h ; Terminal Server aware.

; Section Flags:
IMAGE_SCN_RESERVED1               EQU 00000000h ; Reserved for future use.
IMAGE_SCN_RESERVED2               EQU 00000001h ; Reserved for future use.
IMAGE_SCN_RESERVED3               EQU 00000002h ; Reserved for future use.
IMAGE_SCN_RESERVED4               EQU 00000004h ; Reserved for future use.
IMAGE_SCN_TYPE_NO_PAD             EQU 00000008h ; The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
IMAGE_SCN_RESERVED5               EQU 00000010h ; Reserved for future use.
IMAGE_SCN_CNT_CODE                EQU 00000020h ; The section contains executable code.
IMAGE_SCN_CNT_INITIALIZED_DATA    EQU 00000040h ; The section contains initialized data.
IMAGE_SCN_CNT_UNINITIALIZED_DATA  EQU 00000080h ; The section contains uninitialized data.
IMAGE_SCN_LNK_OTHER               EQU 00000100h ; Reserved for future use.
IMAGE_SCN_LNK_INFO                EQU 00000200h ; The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
IMAGE_SCN_RESERVED6               EQU 00000400h ; Reserved for future use.
IMAGE_SCN_LNK_REMOVE              EQU 00000800h ; The section will not become part of the image. This is valid only for object files.
IMAGE_SCN_LNK_COMDAT              EQU 00001000h ; The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
IMAGE_SCN_GPREL                   EQU 00008000h ; The section contains data referenced through the global pointer (GP).
IMAGE_SCN_MEM_PURGEABLE           EQU 00020000h ; Reserved for future use.
IMAGE_SCN_MEM_16BIT               EQU 00020000h ; Reserved for future use.
IMAGE_SCN_MEM_LOCKED              EQU 00040000h ; Reserved for future use.
IMAGE_SCN_MEM_PRELOAD             EQU 00080000h ; Reserved for future use.
IMAGE_SCN_ALIGN_1BYTES            EQU 00100000h ; Align data on a 1-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_2BYTES            EQU 00200000h ; Align data on a 2-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_4BYTES            EQU 00300000h ; Align data on a 4-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_8BYTES            EQU 00400000h ; Align data on an 8-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_16BYTES           EQU 00500000h ; Align data on a 16-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_32BYTES           EQU 00600000h ; Align data on a 32-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_64BYTES           EQU 00700000h ; Align data on a 64-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_128BYTES          EQU 00800000h ; Align data on a 128-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_256BYTES          EQU 00900000h ; Align data on a 256-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_512BYTES          EQU 00A00000h ; Align data on a 512-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_1024BYTES         EQU 00B00000h ; Align data on a 1024-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_2048BYTES         EQU 00C00000h ; Align data on a 2048-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_4096BYTES         EQU 00D00000h ; Align data on a 4096-byte boundary. Valid only for object files.
IMAGE_SCN_ALIGN_8192BYTES         EQU 00E00000h ; Align data on an 8192-byte boundary. Valid only for object files.
IMAGE_SCN_LNK_NRELOC_OVFL         EQU 01000000h ; The section contains extended relocations.
IMAGE_SCN_MEM_DISCARDABLE         EQU 02000000h ; The section can be discarded as needed.
IMAGE_SCN_MEM_NOT_CACHED          EQU 04000000h ; The section cannot be cached.
IMAGE_SCN_MEM_NOT_PAGED           EQU 08000000h ; The section is not pageable.
IMAGE_SCN_MEM_SHARED              EQU 10000000h ; The section can be shared in memory.
IMAGE_SCN_MEM_EXECUTE             EQU 20000000h ; The section can be executed as code.
IMAGE_SCN_MEM_READ                EQU 40000000h ; The section can be read.
IMAGE_SCN_MEM_WRITE               EQU 80000000h ; The section can be written to. 

; Type Indicators - x64 Processors:
IMAGE_REL_AMD64_ABSOLUTE  EQU 0000h ; The relocation is ignored.
IMAGE_REL_AMD64_ADDR64    EQU 0001h ; The 64-bit VA of the relocation target.
IMAGE_REL_AMD64_ADDR32    EQU 0002h ; The 32-bit VA of the relocation target.
IMAGE_REL_AMD64_ADDR32NB  EQU 0003h ; The 32-bit address without an image base (RVA).
IMAGE_REL_AMD64_REL32     EQU 0004h ; The 32-bit relative address from the byte following the relocation.
IMAGE_REL_AMD64_REL32_1   EQU 0005h ; The 32-bit address relative to byte distance 1 from the relocation.
IMAGE_REL_AMD64_REL32_2   EQU 0006h ; The 32-bit address relative to byte distance 2 from the relocation.
IMAGE_REL_AMD64_REL32_3   EQU 0007h ; The 32-bit address relative to byte distance 3 from the relocation.
IMAGE_REL_AMD64_REL32_4   EQU 0008h ; The 32-bit address relative to byte distance 4 from the relocation.
IMAGE_REL_AMD64_REL32_5   EQU 0009h ; The 32-bit address relative to byte distance 5 from the relocation.
IMAGE_REL_AMD64_SECTION   EQU 000Ah ; The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_AMD64_SECREL    EQU 000Bh ; The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_AMD64_SECREL7   EQU 000Ch ; A 7-bit unsigned offset from the base of the section that contains the target.
IMAGE_REL_AMD64_TOKEN     EQU 000Dh ; CLR tokens.
IMAGE_REL_AMD64_SREL32    EQU 000Eh ; A 32-bit signed span-dependent value emitted into the object.
IMAGE_REL_AMD64_PAIR      EQU 000Fh ; A pair that must immediately follow every span-dependent value.
IMAGE_REL_AMD64_SSPAN32   EQU 0010h ; A 32-bit signed span-dependent value that is applied at link time. 

; Type Indicators - Intel 386 Processors:
IMAGE_REL_I386_ABSOLUTE   EQU 0000h ; The relocation is ignored.
IMAGE_REL_I386_DIR16      EQU 0001h ; Not supported.
IMAGE_REL_I386_REL16      EQU 0002h ; Not supported.
IMAGE_REL_I386_DIR32      EQU 0006h ; The target's 32-bit VA.
IMAGE_REL_I386_DIR32NB    EQU 0007h ; The target's 32-bit RVA.
IMAGE_REL_I386_SEG12      EQU 0009h ; Not supported.
IMAGE_REL_I386_SECTION    EQU 000Ah ; The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_I386_SECREL     EQU 000Bh ; The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_I386_TOKEN      EQU 000Ch ; The CLR token.
IMAGE_REL_I386_SECREL7    EQU 000Dh ; A 7-bit offset from the base of the section that contains the target.
IMAGE_REL_I386_REL32      EQU 0014h ; The 32-bit relative displacement to the target. This supports the x86 relative branch and call instructions. 

; Type Indicators - Intel Itanium Processor Family (IPF):
IMAGE_REL_IA64_ABSOLUTE   EQU 0000h ; The relocation is ignored.
IMAGE_REL_IA64_IMM14      EQU 0001h ; The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address before it is inserted into the specified slot in the IMM14 bundle. The relocation target must be absolute or the image must be fixed.
IMAGE_REL_IA64_IMM22      EQU 0002h ; The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address before it is inserted into the specified slot in the IMM22 bundle. The relocation target must be absolute or the image must be fixed.
IMAGE_REL_IA64_IMM64      EQU 0003h ; The slot number of this relocation must be one (1). The relocation can be followed by an ADDEND relocation whose value is added to the target address before it is stored in all three slots of the IMM64 bundle.
IMAGE_REL_IA64_DIR32      EQU 0004h ; The target's 32-bit VA. This is supported only for /LARGEADDRESSAWARE:NO images.
IMAGE_REL_IA64_DIR64      EQU 0005h ; The target's 64-bit VA.
IMAGE_REL_IA64_PCREL21B   EQU 0006h ; The instruction is fixed up with the 25-bit relative displacement to the 16-bit aligned target. The low 4 bits of the displacement are zero and are not stored.
IMAGE_REL_IA64_PCREL21M   EQU 0007h ; The instruction is fixed up with the 25-bit relative displacement to the 16-bit aligned target. The low 4 bits of the displacement, which are zero, are not stored.
IMAGE_REL_IA64_PCREL21F   EQU 0008h ; The LSBs of this relocation's offset must contain the slot number whereas the rest is the bundle address. 
IMAGE_REL_IA64_GPREL22    EQU 0009h ; The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address and then a 22-bit GP-relative offset that is calculated and applied to the GPREL22 bundle.
IMAGE_REL_IA64_LTOFF22    EQU 000Ah ; The instruction is fixed up with the 22-bit GP-relative offset to the target symbol's literal table entry. The linker creates this literal table entry based on this relocation and the ADDEND relocation that might follow.
IMAGE_REL_IA64_SECTION    EQU 000Bh ; The 16-bit section index of the section contains the target. This is used to support debugging information.
IMAGE_REL_IA64_SECREL22   EQU 000Ch ; The instruction is fixed up with the 22-bit offset of the target from the beginning of its section.
IMAGE_REL_IA64_SECREL64I  EQU 000Dh ; The slot number for this relocation must be one (1). The instruction is fixed up with the 64-bit offset of the target from the beginning of its section.
IMAGE_REL_IA64_SECREL32   EQU 000Eh ; The address of data to be fixed up with the 32-bit offset of the target from the beginning of its section.
IMAGE_REL_IA64_DIR32NB    EQU 0010h ; The target's 32-bit RVA.
IMAGE_REL_IA64_SREL14     EQU 0011h ; This is applied to a signed 14-bit immediate that contains the difference between two relocatable targets. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
IMAGE_REL_IA64_SREL22     EQU 0012h ; This is applied to a signed 22-bit immediate that contains the difference between two relocatable targets. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
IMAGE_REL_IA64_SREL32     EQU 0013h ; This is applied to a signed 32-bit immediate that contains the difference between two relocatable values. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
IMAGE_REL_IA64_UREL32     EQU 0014h ; This is applied to an unsigned 32-bit immediate that contains the difference between two relocatable values. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
IMAGE_REL_IA64_PCREL6     EQU 0015h ; A 60-bit PC-relative fixup that always stays as a BRL instruction of an MLX bundle.
IMAGE_REL_IA64_PCREL60B   EQU 0016h ; A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MBB bundle with NOP.B in slot 1 and a 25-bit BR instruction (with the 4 lowest bits all zero and dropped) in slot 2.
IMAGE_REL_IA64_PCREL60F   EQU 0017h ; A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MFB bundle with NOP.F in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
IMAGE_REL_IA64_PCREL60I   EQU 0018h ; A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MIB bundle with NOP.I in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
IMAGE_REL_IA64_PCREL60M   EQU 0019h ; A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MMB bundle with NOP.M in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
IMAGE_REL_IA64_IMMGPREL64 EQU 001ah ; A 64-bit GP-relative fixup.
IMAGE_REL_IA64_TOKEN      EQU 001bh ; A CLR token.
IMAGE_REL_IA64_GPREL32    EQU 001ch ; A 32-bit GP-relative fixup.
IMAGE_REL_IA64_ADDEND     EQU 001Fh ; The relocation is valid only when it immediately follows one of the following relocations: IMM14, IMM22, IMM64, GPREL22, LTOFF22, LTOFF64, SECREL22, SECREL64I, or SECREL32. 

; Data Directory Indexes:
IMAGE_DIRECTORY_ENTRY_EXPORT         EQU  0 ; Export directory
IMAGE_DIRECTORY_ENTRY_IMPORT         EQU  1 ; Import directory
IMAGE_DIRECTORY_ENTRY_RESOURCE       EQU  2 ; Resource directory 
IMAGE_DIRECTORY_ENTRY_EXCEPTION      EQU  3 ; Exception directory
IMAGE_DIRECTORY_ENTRY_SECURITY       EQU  4 ; Security directory 
IMAGE_DIRECTORY_ENTRY_BASERELOC      EQU  5 ; Base relocation table 
IMAGE_DIRECTORY_ENTRY_DEBUG          EQU  6 ; Debug directory
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   EQU  7 ; Architecture-specific data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR      EQU  8 ; The relative virtual address of global pointer
IMAGE_DIRECTORY_ENTRY_TLS            EQU  9 ; Thread local storage directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    EQU 10 ; Load configuration directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   EQU 11 ; Bound import directory
IMAGE_DIRECTORY_ENTRY_IAT            EQU 12 ; Import address table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   EQU 13 ; Delay import table
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR EQU 14 ; COM descriptor table
IMAGE_DIRECTORY_ENTRY_RESERVED       EQU 15 ; Reserved

IMAGE_NUMBEROF_DIRECTORY_ENTRIES     EQU 16


; Resourece Directory Entry ID Types:
RT_CURSOR           EQU  1 ; Hardware-dependent cursor resource.
RT_BITMAP           EQU  2 ; Bitmap resource.
RT_ICON             EQU  3 ; Hardware-dependent icon resource.
RT_MENU             EQU  4 ; Menu resource.
RT_DIALOG           EQU  5 ; Dialog box.
RT_STRING           EQU  6 ; String-table entry.
RT_FONTDIR          EQU  7 ; Font directory resource.
RT_FONT             EQU  8 ; Font resource.
RT_ACCELERATOR      EQU  9 ; Accelerator table.
RT_RCDATA           EQU 10 ; Application-defined resource (raw data).
RT_MESSAGETABLE     EQU 11 ; Message-table entry.
RT_GROUP_CURSOR     EQU RT_CURSOR + 11 ; 12 - Hardware-independent cursor resource.
RT_GROUP_ICON       EQU RT_ICON + 11 ; 14 - Hardware-independent icon resource.
RT_VERSION          EQU 16 ; Version resource.
RT_DLGINCLUDE       EQU 17 ; Allows a resource editing tool to associate a string with an .rc file.
RT_PLUGPLAY         EQU 19 ; Plug and Play resource.
RT_VXD              EQU 20 ; VXD.
RT_ANICURSOR        EQU 21 ; Animated cursor.
RT_ANIICON          EQU 22 ; Animated icon.
RT_HTML             EQU 23 ; HTML resource.
RT_MANIFEST         EQU 24 ; Side-by-Side Assembly Manifest.






















