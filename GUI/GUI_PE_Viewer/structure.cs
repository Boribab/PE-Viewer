using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections;

using BYTE = System.Byte;
using WORD = System.UInt16;
using DWORD = System.UInt32;
using LONG = System.Int32;
using ULONGLONG = System.UInt64;

namespace structure
{

    [Serializable]
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DOS_HEADER
    {      // DOS .EXE header
        public WORD e_magic;                     // Magic number
        public WORD e_cblp;                      // Bytes on last page of file
        public WORD e_cp;                        // Pages in file
        public WORD e_crlc;                      // Relocations
        public WORD e_cparhdr;                   // Size of header in paragraphs
        public WORD e_minalloc;                  // Minimum extra paragraphs needed
        public WORD e_maxalloc;                  // Maximum extra paragraphs needed
        public WORD e_ss;                        // Initial (relative) SS value
        public WORD e_sp;                        // Initial SP value
        public WORD e_csum;                      // Checksum
        public WORD e_ip;                        // Initial IP value
        public WORD e_cs;                        // Initial (relative) CS value
        public WORD e_lfarlc;                    // File address of relocation table
        public WORD e_ovno;                      // Overlay number
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public WORD[] e_res;       // Reserved words
        public WORD e_oemid;                     // OEM identifier (for e_oeminfo)
        public WORD e_oeminfo;                   // OEM information; e_oemid specific
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public WORD[] e_res2;     // Reserved words
        public LONG e_lfanew;                    // File address of new exe header
    };

    public struct IMAGE_FILE_HEADER
    {
        public WORD Machine;
        public WORD NumberOfSections;
        public DWORD TimeDateStamp;
        public DWORD PointerToSymbolTable;
        public DWORD NumberOfSymbols;
        public WORD SizeOfOptionalHeader;
        public WORD Characteristics;
    };

    public struct IMAGE_DATA_DIRECTORY
    {
        public DWORD VirtualAddress;
        public DWORD Size;
    };

    [Serializable]
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        //
        // Standard fields.
        //

        public WORD Magic;
        public BYTE MajorLinkerVersion;
        public BYTE MinorLinkerVersion;
        public DWORD SizeOfCode;
        public DWORD SizeOfInitializedData;
        public DWORD SizeOfUninitializedData;
        public DWORD AddressOfEntryPoint;
        public DWORD BaseOfCode;
        public DWORD BaseOfData;

        //
        // NT additional fields.
        //

        public DWORD ImageBase;
        public DWORD SectionAlignment;
        public DWORD FileAlignment;
        public WORD MajorOperatingSystemVersion;
        public WORD MinorOperatingSystemVersion;
        public WORD MajorImageVersion;
        public WORD MinorImageVersion;
        public WORD MajorSubsystemVersion;
        public WORD MinorSubsystemVersion;
        public DWORD Win32VersionValue;
        public DWORD SizeOfImage;
        public DWORD SizeOfHeaders;
        public DWORD CheckSum;
        public WORD Subsystem;
        public WORD DllCharacteristics;
        public DWORD SizeOfStackReserve;
        public DWORD SizeOfStackCommit;
        public DWORD SizeOfHeapReserve;
        public DWORD SizeOfHeapCommit;
        public DWORD LoaderFlags;
        public DWORD NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    };

    [Serializable]
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public WORD Magic;
        public BYTE MajorLinkerVersion;
        public BYTE MinorLinkerVersion;
        public DWORD SizeOfCode;
        public DWORD SizeOfInitializedData;
        public DWORD SizeOfUninitializedData;
        public DWORD AddressOfEntryPoint;
        public DWORD BaseOfCode;
        public ULONGLONG ImageBase;
        public DWORD SectionAlignment;
        public DWORD FileAlignment;
        public WORD MajorOperatingSystemVersion;
        public WORD MinorOperatingSystemVersion;
        public WORD MajorImageVersion;
        public WORD MinorImageVersion;
        public WORD MajorSubsystemVersion;
        public WORD MinorSubsystemVersion;
        public DWORD Win32VersionValue;
        public DWORD SizeOfImage;
        public DWORD SizeOfHeaders;
        public DWORD CheckSum;
        public WORD Subsystem;
        public WORD DllCharacteristics;
        public ULONGLONG SizeOfStackReserve;
        public ULONGLONG SizeOfStackCommit;
        public ULONGLONG SizeOfHeapReserve;
        public ULONGLONG SizeOfHeapCommit;
        public DWORD LoaderFlags;
        public DWORD NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    };

    public struct IMAGE_NT_HEADERS
    {
        public DWORD Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    };

    public struct IMAGE_NT_HEADERS64
    {
        public DWORD Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    };

    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public BYTE[] Name;
        public DWORD PhysicalAddress;
        public DWORD VirtualSize;
        public DWORD VirtualAddress;
        public DWORD SizeOfRawData;
        public DWORD PointerToRawData;
        public DWORD PointerToRelocations;
        public DWORD PointerToLinenumbers;
        public WORD NumberOfRelocations;
        public WORD NumberOfLinenumbers;
        public DWORD Characteristics;
    };
}
