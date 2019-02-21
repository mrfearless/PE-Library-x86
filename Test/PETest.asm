.686
.MMX
.XMM
.model flat,stdcall
option casemap:none

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
includelib PE.lib

CTEXT MACRO Text                        ; Macro for defining text in place 
    LOCAL szText
    .DATA
    szText DB Text, 0
    .CODE
    EXITM <Offset szText>
ENDM

Main                PROTO               ; Console Main procedure
DoPEFile            PROTO               ; Do PE Tests

ConsoleStdOut       PROTO :DWORD        ; Print console text
ConsoleClearScreen  PROTO               ; Clear console screen
DwordToAscii        PROTO :DWORD,:DWORD ; Convert dword to ascii string

.DATA
szCRLF              DB 13,10,0          ; Carriage Return and Line Feed
szTest              DB '.\PETest.exe',0 ; Ourself
szValueBuffer       DB 16 DUP (0)       ; Buffer for DwordToAscii

.DATA?
hPE                 DD ?                ; PE Handle 

.CODE

;------------------------------------------------------------------------------
; Main procedure
;------------------------------------------------------------------------------
Main PROC
    Invoke ConsoleClearScreen
    Invoke ConsoleStdOut, CTEXT("PETest - Test program for PE Library x86")
    Invoke ConsoleStdOut, Addr szCRLF
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke DoPEFile
    
    Invoke ExitProcess,0
    ret
Main ENDP

;------------------------------------------------------------------------------
; PE file tests
;------------------------------------------------------------------------------
DoPEFile PROC
    LOCAL dwErrorNo:DWORD
    LOCAL pHeaderDOS:DWORD
    LOCAL pHeaderNT:DWORD
    LOCAL pHeaderFile:DWORD
    LOCAL pHeaderOptional:DWORD
    LOCAL pHeaderSections:DWORD
    LOCAL dwSectionCount:DWORD    
    LOCAL dwMachine:DWORD
    LOCAL dwCharacteristics:DWORD
    LOCAL dwLinkerVersion:DWORD
    LOCAL dwMajorLinkerVersion:DWORD
    LOCAL dwMinorLinkerVersion:DWORD
    LOCAL dwAddressOfEntryPoint:DWORD
    LOCAL dwImageBase:DWORD
    LOCAL qwImageBase:QWORD
    LOCAL dwSizeOfImage:DWORD
    LOCAL dwCheckSum:DWORD
    LOCAL dwSubsystem:DWORD
    LOCAL dwDllCharacteristics:DWORD
    LOCAL bPEDLL:DWORD
    LOCAL bPE64:DWORD

    ;--------------------------------------------------------------------------
    ; Open PE file (ourself: PEText.exe)
    ;--------------------------------------------------------------------------
    Invoke PE_OpenFile, Addr szTest, TRUE, Addr hPE
    .IF eax == FALSE
        Invoke PE_GetError
        mov dwErrorNo, eax
        Invoke ConsoleStdOut, CTEXT("Error: ")
        Invoke DwordToAscii, dwErrorNo, Addr szValueBuffer
        Invoke ConsoleStdOut, Addr szValueBuffer
        Invoke ConsoleStdOut, Addr szCRLF        
        IFDEF DEBUG32
        PrintDec dwErrorNo
        ENDIF
        ret
    .ENDIF

    ;--------------------------------------------------------------------------
    ; Get pointers to various PE structures:
    ;--------------------------------------------------------------------------
    Invoke PE_HeaderDOS, hPE
    mov pHeaderDOS, eax
    Invoke PE_HeaderNT, hPE
    mov pHeaderNT, eax
    Invoke PE_HeaderFile, hPE
    mov pHeaderFile, eax
    Invoke PE_HeaderOptional, hPE
    mov pHeaderOptional, eax
    Invoke PE_HeaderSections, hPE
    mov pHeaderSections, eax
    Invoke PE_SectionHeaderCount, hPE
    mov dwSectionCount, eax

    IFDEF DEBUG32
        PrintDec hPE
        PrintDec pHeaderDOS
        PrintDec pHeaderNT
        PrintDec pHeaderFile
        PrintDec pHeaderOptional
        PrintDec pHeaderSections
        PrintDec dwSectionCount
        mov eax, dwSectionCount
        mov ebx, SIZEOF IMAGE_SECTION_HEADER
        mul ebx
        DbgDump pHeaderSections, eax 
    ENDIF
    
    ;--------------------------------------------------------------------------
    ; Get information from PE:
    ;--------------------------------------------------------------------------
    Invoke PE_IsDll, hPE
    mov bPEDLL, eax
    Invoke PE_Is64, hPE
    mov bPE64, eax    
    Invoke PE_Machine, hPE
    mov dwMachine, eax
    Invoke PE_Characteristics, hPE
    mov dwCharacteristics, eax
    Invoke PE_LinkerVersion, hPE
    mov dwLinkerVersion, eax
    xor ebx, ebx
    mov bl, al
    mov dwMinorLinkerVersion, ebx
    mov bl, ah
    mov dwMajorLinkerVersion, ebx
    Invoke PE_AddressOfEntryPoint, hPE
    mov dwAddressOfEntryPoint, eax
    Invoke PE_ImageBase, hPE
    .IF bPE64 == TRUE
        mov dword ptr [qwImageBase], eax
        mov dword ptr [qwImageBase+4], edx
    .ELSE
        mov dwImageBase, eax
    .ENDIF
    Invoke PE_SizeOfImage, hPE
    mov dwSizeOfImage, eax
    Invoke PE_CheckSum, hPE
    mov dwCheckSum, eax
    Invoke PE_Subsystem, hPE
    mov dwSubsystem, eax
    Invoke PE_DllCharacteristics, hPE
    mov dwDllCharacteristics, eax
    
    ;--------------------------------------------------------------------------
    ; Output PE information:
    ;--------------------------------------------------------------------------
    Invoke ConsoleStdOut, CTEXT("hPE: ")
    Invoke DwordToAscii, hPE, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, CTEXT("pHeaderDOS: ")
    Invoke DwordToAscii, pHeaderDOS, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, CTEXT("pHeaderNT: ")
    Invoke DwordToAscii, pHeaderNT, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, CTEXT("pHeaderFile: ")
    Invoke DwordToAscii, pHeaderFile, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, CTEXT("pHeaderOptional: ")
    Invoke DwordToAscii, pHeaderOptional, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, CTEXT("pHeaderSections: ")
    Invoke DwordToAscii, pHeaderSections, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, CTEXT("No of sections: ")
    Invoke DwordToAscii, dwSectionCount, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, Addr szCRLF
    
    ; Information
    Invoke ConsoleStdOut, CTEXT("Machine: ")
    Invoke DwordToAscii, dwMachine, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, CTEXT("Characteristics: ")
    Invoke DwordToAscii, dwCharacteristics, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF

    Invoke ConsoleStdOut, CTEXT("MajorLinkerVersion: ")
    Invoke DwordToAscii, dwMajorLinkerVersion, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF
    
    Invoke ConsoleStdOut, CTEXT("MinorLinkerVersion: ")
    Invoke DwordToAscii, dwMinorLinkerVersion, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF

    Invoke ConsoleStdOut, CTEXT("AddressOfEntryPoint: ")
    Invoke DwordToAscii, dwAddressOfEntryPoint, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF

    Invoke ConsoleStdOut, CTEXT("ImageBase: ")
    .IF bPE64 == TRUE
        mov eax, dword ptr [qwImageBase+4]
        mov dwImageBase, eax
        Invoke DwordToAscii, dwImageBase, Addr szValueBuffer
        Invoke ConsoleStdOut, Addr szValueBuffer
        mov eax, dword ptr [qwImageBase]
        mov dwImageBase, eax
        Invoke DwordToAscii, dwImageBase, Addr szValueBuffer
        Invoke ConsoleStdOut, Addr szValueBuffer
    .ELSE
        Invoke DwordToAscii, dwImageBase, Addr szValueBuffer
        Invoke ConsoleStdOut, Addr szValueBuffer
    .ENDIF
    Invoke ConsoleStdOut, Addr szCRLF

    Invoke ConsoleStdOut, CTEXT("SizeOfImage: ")
    Invoke DwordToAscii, dwSizeOfImage, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF

    Invoke ConsoleStdOut, CTEXT("CheckSum: ")
    Invoke DwordToAscii, dwCheckSum, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF

    Invoke ConsoleStdOut, CTEXT("Subsystem: ")
    Invoke DwordToAscii, dwSubsystem, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF

    Invoke ConsoleStdOut, CTEXT("DllCharacteristics: ")
    Invoke DwordToAscii, dwDllCharacteristics, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szValueBuffer
    Invoke ConsoleStdOut, Addr szCRLF

    ;--------------------------------------------------------------------------
    ; Close PE file. hPE will be set to NULL automatically
    ;--------------------------------------------------------------------------
    Invoke PE_CloseFile, hPE    
    
    IFDEF DEBUG32
    PrintDec hPE
    ENDIF
    
    ret
DoPEFile ENDP

;------------------------------------------------------------------------------
; ConsoleStdOut - taken from masm32 lib
;------------------------------------------------------------------------------
ConsoleStdOut PROC lpszConText:DWORD
    LOCAL hConOutput:DWORD
    LOCAL dwBytesWritten:DWORD
    LOCAL dwLenConText:DWORD

    Invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov hConOutput, eax

    Invoke lstrlen, lpszConText
    mov dwLenConText, eax

    Invoke WriteFile, hConOutput, lpszConText, dwLenConText, Addr dwBytesWritten, NULL

    mov eax, dwBytesWritten
    ret
ConsoleStdOut ENDP

;------------------------------------------------------------------------------
; ClearConsoleScreen - taken from masm32 lib
;------------------------------------------------------------------------------
ConsoleClearScreen PROC USES EBX
    LOCAL hConOutput:DWORD
    LOCAL noc:DWORD
    LOCAL cnt:DWORD
    LOCAL sbi:CONSOLE_SCREEN_BUFFER_INFO

    Invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov hConOutput, eax

    Invoke GetConsoleScreenBufferInfo, hConOutput, Addr sbi
    mov eax, sbi.dwSize ; 2 word values returned for screen size

    ; extract the 2 values and multiply them together
    mov ebx, eax
    shr eax, 16
    mul bx
    mov cnt, eax

    Invoke FillConsoleOutputCharacter, hConOutput, 32, cnt, NULL, Addr noc
    movzx ebx, sbi.wAttributes
    Invoke FillConsoleOutputAttribute, hConOutput, ebx, cnt, NULL, Addr noc
    Invoke SetConsoleCursorPosition, hConOutput, NULL
    ret
ConsoleClearScreen ENDP

;------------------------------------------------------------------------------
; DwordToAscii - Paul Dixon's utoa_ex function. unsigned dword to ascii.
; Returns: Buffer pointed to by lpszAsciiString will contain ascii string
;------------------------------------------------------------------------------
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
DwordToAscii PROC dwValue:DWORD, lpszAsciiString:DWORD
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
DwordToAscii ENDP
OPTION PROLOGUE:PrologueDef
OPTION EPILOGUE:EpilogueDef


END Main

















