#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <winNT.h>
#pragma warning (disable:4996)

IMAGE_DOS_HEADER IDH;
IMAGE_NT_HEADERS INH_32;
IMAGE_NT_HEADERS64 INH_64;
IMAGE_SECTION_HEADER *ISH; // text data rsrc

FILE *fp;

char* dos_header_data;
char* nt_header_data;
char* section_header_data;

void print_DOS_Header(IMAGE_DOS_HEADER IDH)
{
	int num = 0;
	printf("******** DOS MZ Header ********\n");
	printf("%08X		%04X			Signature\n", num, IDH.e_magic);
	num += sizeof(IDH.e_magic);
	printf("%08X		%04X			Bytes on last page of file\n", num, IDH.e_cblp);
	num += sizeof(IDH.e_cblp);
	printf("%08X		%04X			Pages in file\n", num, IDH.e_cp);
	num += sizeof(IDH.e_cp);
	printf("%08X		%04X			Relecations\n", num, IDH.e_crlc);
	num += sizeof(IDH.e_crlc);
	printf("%08X		%04X			Size of header in paragraphs\n", num, IDH.e_cparhdr);
	num += sizeof(IDH.e_cparhdr);
	printf("%08X		%04X			Minimum extra paragraphs needed\n", num, IDH.e_minalloc);
	num += sizeof(IDH.e_minalloc);
	printf("%08X		%04X			Maximum extra paragraphs needed\n", num, IDH.e_maxalloc);
	num += sizeof(IDH.e_maxalloc);
	printf("%08X		%04X			Initial (relative) SS value\n", num, IDH.e_ss);
	num += sizeof(IDH.e_ss);
	printf("%08X		%04X			Initial SP value\n", num, IDH.e_sp);
	num += sizeof(IDH.e_sp);
	printf("%08X		%04X			Checksum\n", num, IDH.e_csum);
	num += sizeof(IDH.e_csum);
	printf("%08X		%04X			Initial IP value\n", num, IDH.e_ip);
	num += sizeof(IDH.e_ip);
	printf("%08X		%04X			Initial (relative) CS value\n", num, IDH.e_cs);
	num += sizeof(IDH.e_cs);
	printf("%08X		%04X			File address of relocation table\n", num, IDH.e_lfarlc);
	num += sizeof(IDH.e_lfarlc);
	printf("%08X		%04X			Overlay number\n", num, IDH.e_ovno);
	num += sizeof(IDH.e_ovno);
	printf("%08X		%08X		Reserved words\n", num, IDH.e_res);
	num += sizeof(IDH.e_res);
	printf("%08X		%04X			OEM identifier (for e_oeminfo)\n", num, IDH.e_oemid);
	num += sizeof(IDH.e_oemid);
	printf("%08X		%04X			OEM information; e_oemid specific\n", num, IDH.e_oeminfo);
	num += sizeof(IDH.e_oeminfo);
	printf("%08X		%020X	Reserved words\n", num, IDH.e_res2);
	num += sizeof(IDH.e_res2);
	printf("%08X		%04X			File address of new exe header\n", num, IDH.e_lfanew);
	num += sizeof(IDH.e_lfanew);
}

void print_NT_header_64(IMAGE_NT_HEADERS64 INH)
{
	int num = IDH.e_lfanew;
	char DataDirector_name[16][30] = { "EXPORT Directory", "IMPORT Directory", "RESOURCE Directory", "EXCEPTION Directory", "SECURITY Directory",
							"BASERELOC Directory", "DEBUG Directory", "COPYRIGHT Directory", "GLOBALPTR Directory", "TLS Directory", "LOAD_CONFIG Directory",
							"BOUND_IMPORT Directory", "IAT Directory", "DELAY_IMPORT Directory", "COM_DESCRIPTOR Directory", "Reserved Directory"};
	printf("******** PE File Signature ********\n");
	printf("%08X		%08X		Signature\n\n", num, INH.Signature);
	num += sizeof(INH.Signature);
	printf("******** PE File Header ********\n");
	printf("%08X		%04X			Machine\n", num, INH.FileHeader.Machine);
	num += sizeof(INH.FileHeader.Machine);
	printf("%08X		%04X			Number of Section\n", num, INH.FileHeader.NumberOfSections);
	num += sizeof(INH.FileHeader.NumberOfSections);
	printf("%08X		%08X		Time Date Stamp\n", num, INH.FileHeader.TimeDateStamp);
	num += sizeof(INH.FileHeader.TimeDateStamp);
	printf("%08X		%08X		Pointer To Symbol Table\n", num, INH.FileHeader.PointerToSymbolTable);
	num += sizeof(INH.FileHeader.PointerToSymbolTable);
	printf("%08X		%08X		Number Of Symbols\n", num, INH.FileHeader.NumberOfSymbols);
	num += sizeof(INH.FileHeader.NumberOfSymbols);
	printf("%08X		%04X			Size Of Optional Header\n", num, INH.FileHeader.SizeOfOptionalHeader);
	num += sizeof(INH.FileHeader.SizeOfOptionalHeader);
	printf("%08X		%04X			Characteristics\n\n", num, INH.FileHeader.Characteristics);
	num += sizeof(INH.FileHeader.Characteristics);
	printf("******** PE File Optional Header ********\n");
	printf("%08X		%04X			Magic\n", num, INH.OptionalHeader.Magic);
	num += sizeof(INH.OptionalHeader.Magic);
	printf("%08X		%02X			Major Linker Version\n", num, INH.OptionalHeader.MajorLinkerVersion);
	num += sizeof(INH.OptionalHeader.MajorLinkerVersion);
	printf("%08X		%02X			Minor Linker Version\n", num, INH.OptionalHeader.MinorLinkerVersion);
	num += sizeof(INH.OptionalHeader.MinorLinkerVersion);
	printf("%08X		%08X		Size Of Code\n", num, INH.OptionalHeader.SizeOfCode);
	num += sizeof(INH.OptionalHeader.SizeOfCode);
	printf("%08X		%08X		Size Of Initialized Data\n", num, INH.OptionalHeader.SizeOfInitializedData);
	num += sizeof(INH.OptionalHeader.SizeOfInitializedData);
	printf("%08X		%08X		Size Of Uninitialized Data\n", num, INH.OptionalHeader.SizeOfUninitializedData);
	num += sizeof(INH.OptionalHeader.SizeOfUninitializedData);
	printf("%08X		%08X		Address Of Entry Point\n", num, INH.OptionalHeader.AddressOfEntryPoint);
	num += sizeof(INH.OptionalHeader.AddressOfEntryPoint);
	printf("%08X		%08X		Base Of Code\n", num, INH.OptionalHeader.BaseOfCode);
	num += sizeof(INH.OptionalHeader.BaseOfCode);
	printf("%08X		%016X	Image Base\n", num, INH.OptionalHeader.ImageBase);
	num += sizeof(INH.OptionalHeader.ImageBase);
	printf("%08X		%08X		Section Alignment\n", num, INH.OptionalHeader.SectionAlignment);
	num += sizeof(INH.OptionalHeader.SectionAlignment);
	printf("%08X		%08X		File Alignment\n", num, INH.OptionalHeader.FileAlignment);
	num += sizeof(INH.OptionalHeader.FileAlignment);
	printf("%08X		%04X			Major Operating System Version\n", num, INH.OptionalHeader.MajorOperatingSystemVersion);
	num += sizeof(INH.OptionalHeader.MajorOperatingSystemVersion);
	printf("%08X		%04X			Minor Operating System Version\n", num, INH.OptionalHeader.MinorOperatingSystemVersion);
	num += sizeof(INH.OptionalHeader.MinorOperatingSystemVersion);
	printf("%08X		%04X			Major Image Version\n", num, INH.OptionalHeader.MajorImageVersion);
	num += sizeof(INH.OptionalHeader.MajorImageVersion);
	printf("%08X		%04X			Minor Image Version\n", num, INH.OptionalHeader.MinorImageVersion);
	num += sizeof(INH.OptionalHeader.MinorImageVersion);
	printf("%08X		%04X			Major Subsystem Version\n", num, INH.OptionalHeader.MajorSubsystemVersion);
	num += sizeof(INH.OptionalHeader.MajorSubsystemVersion);
	printf("%08X		%04X			Minor Subsystem Version\n", num, INH.OptionalHeader.MinorSubsystemVersion);
	num += sizeof(INH.OptionalHeader.MinorSubsystemVersion);
	printf("%08X		%08X		Win32 Version Value\n", num, INH.OptionalHeader.Win32VersionValue);
	num += sizeof(INH.OptionalHeader.Win32VersionValue);
	printf("%08X		%08X		Size Of Image\n", num, INH.OptionalHeader.SizeOfImage);
	num += sizeof(INH.OptionalHeader.SizeOfImage);
	printf("%08X		%08X		Size Of Headers\n", num, INH.OptionalHeader.SizeOfHeaders);
	num += sizeof(INH.OptionalHeader.SizeOfHeaders);
	printf("%08X		%08X		Check Sum\n", num, INH.OptionalHeader.CheckSum);
	num += sizeof(INH.OptionalHeader.CheckSum);
	printf("%08X		%04X			Subsystem\n", num, INH.OptionalHeader.Subsystem);
	num += sizeof(INH.OptionalHeader.Subsystem);
	printf("%08X		%04X			Dll Characteristics\n", num, INH.OptionalHeader.DllCharacteristics);
	num += sizeof(INH.OptionalHeader.DllCharacteristics);
	printf("%08X		%016X	Size Of Stack Reserve\n", num, INH.OptionalHeader.SizeOfStackReserve);
	num += sizeof(INH.OptionalHeader.SizeOfStackReserve);
	printf("%08X		%016X	Size Of Stack Commit\n", num, INH.OptionalHeader.SizeOfStackCommit);
	num += sizeof(INH.OptionalHeader.SizeOfStackCommit);
	printf("%08X		%016X	Size Of Heap Reserve\n", num, INH.OptionalHeader.SizeOfHeapReserve);
	num += sizeof(INH.OptionalHeader.SizeOfHeapReserve);
	printf("%08X		%016X	Size Of Heap Commit\n", num, INH.OptionalHeader.SizeOfHeapCommit);
	num += sizeof(INH.OptionalHeader.SizeOfHeapCommit);
	printf("%08X		%08X		Loader Flags\n", num, INH.OptionalHeader.LoaderFlags);
	num += sizeof(INH.OptionalHeader.LoaderFlags);
	printf("%08X		%08X		Number Of Rva And Sizes\n\n", num, INH.OptionalHeader.NumberOfRvaAndSizes);
	num += sizeof(INH.OptionalHeader.NumberOfRvaAndSizes);
	printf("******** Data Directory ********\n\n");
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		printf("- %s\n", DataDirector_name[i]);
		printf("%08X		%08X		Virtual Address\n", num, INH.OptionalHeader.DataDirectory[i].VirtualAddress);
		num += sizeof(INH.OptionalHeader.DataDirectory[i].VirtualAddress);
		printf("%08X		%08X		Size\n\n", num, INH.OptionalHeader.DataDirectory[i].Size);
		num += sizeof(INH.OptionalHeader.DataDirectory[i].Size);
	}
}

void print_NT_header_32(IMAGE_NT_HEADERS INH)
{
	int num = IDH.e_lfanew;
	char DataDirector_name[16][30] = { "EXPORT Directory", "IMPORT Directory", "RESOURCE Directory", "EXCEPTION Directory", "SECURITY Directory",
							"BASERELOC Directory", "DEBUG Directory", "COPYRIGHT Directory", "GLOBALPTR Directory", "TLS Directory", "LOAD_CONFIG Directory",
							"BOUND_IMPORT Directory", "IAT Directory", "DELAY_IMPORT Directory", "COM_DESCRIPTOR Directory", "Reserved Directory" };
	printf("******** PE File Signature ********\n");
	printf("%08X		%08X	Signature\n\n", num, INH.Signature);
	num += sizeof(INH.Signature);
	printf("******** PE File Header ********\n");
	printf("%08X		%04X		Machine\n", num, INH.FileHeader.Machine);
	num += sizeof(INH.FileHeader.Machine);
	printf("%08X		%04X		Number of Section\n", num, INH.FileHeader.NumberOfSections);
	num += sizeof(INH.FileHeader.NumberOfSections);
	printf("%08X		%08X	Time Date Stamp\n", num, INH.FileHeader.TimeDateStamp);
	num += sizeof(INH.FileHeader.TimeDateStamp);
	printf("%08X		%08X	Pointer To Symbol Table\n", num, INH.FileHeader.PointerToSymbolTable);
	num += sizeof(INH.FileHeader.PointerToSymbolTable);
	printf("%08X		%08X	Number Of Symbols\n", num, INH.FileHeader.NumberOfSymbols);
	num += sizeof(INH.FileHeader.NumberOfSymbols);
	printf("%08X		%04X		Size Of Optional Header\n", num, INH.FileHeader.SizeOfOptionalHeader);
	num += sizeof(INH.FileHeader.SizeOfOptionalHeader);
	printf("%08X		%04X		Characteristics\n\n", num, INH.FileHeader.Characteristics);
	num += sizeof(INH.FileHeader.Characteristics);
	printf("******** PE File Optional Header ********\n");
	printf("%08X		%04X		Magic\n", num, INH.OptionalHeader.Magic);
	num += sizeof(INH.OptionalHeader.Magic);
	printf("%08X		%02X		Major Linker Version\n", num, INH.OptionalHeader.MajorLinkerVersion);
	num += sizeof(INH.OptionalHeader.MajorLinkerVersion);
	printf("%08X		%02X		Minor Linker Version\n", num, INH.OptionalHeader.MinorLinkerVersion);
	num += sizeof(INH.OptionalHeader.MinorLinkerVersion);
	printf("%08X		%08X	Size Of Code\n", num, INH.OptionalHeader.SizeOfCode);
	num += sizeof(INH.OptionalHeader.SizeOfCode);
	printf("%08X		%08X	Size Of Initialized Data\n", num, INH.OptionalHeader.SizeOfInitializedData);
	num += sizeof(INH.OptionalHeader.SizeOfInitializedData);
	printf("%08X		%08X	Size Of Uninitialized Data\n", num, INH.OptionalHeader.SizeOfUninitializedData);
	num += sizeof(INH.OptionalHeader.SizeOfUninitializedData);
	printf("%08X		%08X	Address Of Entry Point\n", num, INH.OptionalHeader.AddressOfEntryPoint);
	num += sizeof(INH.OptionalHeader.AddressOfEntryPoint);
	printf("%08X		%08X	Base Of Code\n", num, INH.OptionalHeader.BaseOfCode);
	num += sizeof(INH.OptionalHeader.BaseOfCode);
	printf("%08X		%08X	Base Of Data\n", num, INH.OptionalHeader.BaseOfData);
	num += sizeof(INH.OptionalHeader.BaseOfData);
	printf("%08X		%08X	Image Base\n", num, INH.OptionalHeader.ImageBase);
	num += sizeof(INH.OptionalHeader.ImageBase);
	printf("%08X		%08X	Section Alignment\n", num, INH.OptionalHeader.SectionAlignment);
	num += sizeof(INH.OptionalHeader.SectionAlignment);
	printf("%08X		%08X	File Alignment\n", num, INH.OptionalHeader.FileAlignment);
	num += sizeof(INH.OptionalHeader.FileAlignment);
	printf("%08X		%04X		Major Operating System Version\n", num, INH.OptionalHeader.MajorOperatingSystemVersion);
	num += sizeof(INH.OptionalHeader.MajorOperatingSystemVersion);
	printf("%08X		%04X		Minor Operating System Version\n", num, INH.OptionalHeader.MinorOperatingSystemVersion);
	num += sizeof(INH.OptionalHeader.MinorOperatingSystemVersion);
	printf("%08X		%04X		Major Image Version\n", num, INH.OptionalHeader.MajorImageVersion);
	num += sizeof(INH.OptionalHeader.MajorImageVersion);
	printf("%08X		%04X		Minor Image Version\n", num, INH.OptionalHeader.MinorImageVersion);
	num += sizeof(INH.OptionalHeader.MinorImageVersion);
	printf("%08X		%04X		Major Subsystem Version\n", num, INH.OptionalHeader.MajorSubsystemVersion);
	num += sizeof(INH.OptionalHeader.MajorSubsystemVersion);
	printf("%08X		%04X		Minor Subsystem Version\n", num, INH.OptionalHeader.MinorSubsystemVersion);
	num += sizeof(INH.OptionalHeader.MinorSubsystemVersion);
	printf("%08X		%08X	Win32 Version Value\n", num, INH.OptionalHeader.Win32VersionValue);
	num += sizeof(INH.OptionalHeader.Win32VersionValue);
	printf("%08X		%08X	Size Of Image\n", num, INH.OptionalHeader.SizeOfImage);
	num += sizeof(INH.OptionalHeader.SizeOfImage);
	printf("%08X		%08X	Size Of Headers\n", num, INH.OptionalHeader.SizeOfHeaders);
	num += sizeof(INH.OptionalHeader.SizeOfHeaders);
	printf("%08X		%08X	Check Sum\n", num, INH.OptionalHeader.CheckSum);
	num += sizeof(INH.OptionalHeader.CheckSum);
	printf("%08X		%04X		Subsystem\n", num, INH.OptionalHeader.Subsystem);
	num += sizeof(INH.OptionalHeader.Subsystem);
	printf("%08X		%04X		Dll Characteristics\n", num, INH.OptionalHeader.DllCharacteristics);
	num += sizeof(INH.OptionalHeader.DllCharacteristics);
	printf("%08X		%08X	Size Of Stack Reserve\n", num, INH.OptionalHeader.SizeOfStackReserve);
	num += sizeof(INH.OptionalHeader.SizeOfStackReserve);
	printf("%08X		%08X	Size Of Stack Commit\n", num, INH.OptionalHeader.SizeOfStackCommit);
	num += sizeof(INH.OptionalHeader.SizeOfStackCommit);
	printf("%08X		%08X	Size Of Heap Reserve\n", num, INH.OptionalHeader.SizeOfHeapReserve);
	num += sizeof(INH.OptionalHeader.SizeOfHeapReserve);
	printf("%08X		%08X	Size Of Heap Commit\n", num, INH.OptionalHeader.SizeOfHeapCommit);
	num += sizeof(INH.OptionalHeader.SizeOfHeapCommit);
	printf("%08X		%08X	Loader Flags\n", num, INH.OptionalHeader.LoaderFlags);
	num += sizeof(INH.OptionalHeader.LoaderFlags);
	printf("%08X		%08X	Number Of Rva And Sizes\n\n", num, INH.OptionalHeader.NumberOfRvaAndSizes);
	num += sizeof(INH.OptionalHeader.NumberOfRvaAndSizes);
	printf("******** Data Directory ********\n\n");
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		printf("- %s\n", DataDirector_name[i]);
		printf("%08X		%08X	Virtual Address\n", num, INH.OptionalHeader.DataDirectory[i].VirtualAddress);
		num += sizeof(INH.OptionalHeader.DataDirectory[i].VirtualAddress);
		printf("%08X		%08X	Size\n\n", num, INH.OptionalHeader.DataDirectory[i].Size);
		num += sizeof(INH.OptionalHeader.DataDirectory[i].Size);
	}
}

void print_Section_header(IMAGE_SECTION_HEADER * ISH, int section_num)
{
	int num;
	if (INH_32.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		num = IDH.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
	}
	else
	{
		num = IDH.e_lfanew + sizeof(IMAGE_NT_HEADERS);
	}

	//printf("******** Section Header ********\n\n");

	for (int i = 0; i < section_num; i++)
	{
		printf("- %s\n", ISH[i].Name);
		num += sizeof(ISH[i].Name);
		printf("%08X		%08X	Virtual Size\n", num, ISH[i].Misc);
		num += sizeof(ISH[i].Misc);
		printf("%08X		%08X	Virtual Address\n", num, ISH[i].VirtualAddress);
		num += sizeof(ISH[i].VirtualAddress);
		printf("%08X		%08X	Size Of Raw Data\n", num, ISH[i].SizeOfRawData);
		num += sizeof(ISH[i].SizeOfRawData);
		printf("%08X		%08X	Pointer To Raw Data\n", num, ISH[i].PointerToRawData);
		num += sizeof(ISH[i].PointerToRawData);
		printf("%08X		%08X	Pointer To Relocations\n", num, ISH[i].PointerToRelocations);
		num += sizeof(ISH[i].PointerToRelocations);
		printf("%08X		%08X	Pointer To Linenumbers\n", num, ISH[i].PointerToLinenumbers);
		num += sizeof(ISH[i].PointerToLinenumbers);
		printf("%08X		%04X		Number Of Relocations\n", num, ISH[i].NumberOfRelocations);
		num += sizeof(ISH[i].NumberOfRelocations);
		printf("%08X		%04X		Number Of Linenumbers\n", num, ISH[i].NumberOfLinenumbers);
		num += sizeof(ISH[i].NumberOfLinenumbers);
		printf("%08X		%08X	Characteristics\n\n", num, ISH[i].Characteristics);
		num += sizeof(ISH[i].Characteristics);
	}
}

int main()
{
	int n, flag = 0;
	char path[250];
	int IDH_size = 0, INH_size = 0, ISH_size = 0;

	IDH_size = sizeof(IDH);
	INH_size = sizeof(IMAGE_NT_HEADERS64);
	ISH_size = sizeof(IMAGE_SECTION_HEADER);

	dos_header_data = (char *)malloc(IDH_size * sizeof(char));
	nt_header_data = (char *)malloc(INH_size * sizeof(char));
	section_header_data = (char *)malloc(ISH_size * sizeof(char));

	while (1)
	{
		printf("1. File Open\n2. DOS Header\n3. NT Header\n4. Section Header\n5. Exit\n->");
		scanf("%d", &n);

		if (n < 1 || n > 5)
		{
			system("cls");
			continue;
		}

		switch (n)
		{
		case 1:
		{
			system("cls");
			printf("File Path : ");
			scanf("%s", path);
			fp = fopen(path, "rb");

			if (fp == NULL)
			{
				system("cls");
				printf("Can't Open the file\n\n");
				continue;
			}
			// dos header 불러오기
			fread(dos_header_data, sizeof(char), IDH_size, fp);
			memcpy(&IDH, dos_header_data, IDH_size);

			// NT header 불러오기
			fseek(fp, IDH.e_lfanew, SEEK_SET);
			fread(nt_header_data, sizeof(char), INH_size, fp);
			memcpy(&INH_32, nt_header_data, INH_size);
			if (INH_32.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			{
				INH_size = sizeof(INH_64);
				fseek(fp, IDH.e_lfanew, SEEK_SET);
				fread(nt_header_data, sizeof(char), INH_size, fp);
				memcpy(&INH_64, nt_header_data, INH_size);
			}

			// Section header 불러오기
			ISH = (IMAGE_SECTION_HEADER *)malloc(INH_32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			flag = 1;

			for (int i = 0; i < INH_32.FileHeader.NumberOfSections; i++)
			{
				fseek(fp, IDH.e_lfanew + INH_size + (ISH_size * i), SEEK_SET);
				fread(section_header_data, sizeof(char), ISH_size, fp);
				memcpy(&ISH[i], section_header_data, ISH_size);
			}

			system("cls");
			printf("Open File Complete\n\n");
			break;
		}
		case 2:
		{
			if (fp == NULL)
			{
				system("cls");
				printf("Open the file first\n\n");
				break;
			}

			print_DOS_Header(IDH);
			printf("Press any key to continue...");
			getch();
			system("cls");
			break;
		}
		case 3:
		{
			if (fp == NULL)
			{
				system("cls");
				printf("Open the file first\n\n");
				break;
			}

			if (INH_32.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			{
				print_NT_header_64(INH_64);
			}
			else
			{
				print_NT_header_32(INH_32);
			}
			printf("Press any key to continue...");
			getch();
			system("cls");
			break;
		}
		case 4:
		{
			if (fp == NULL)
			{
				system("cls");
				printf("Open the file first\n\n");
				break;
			}

			print_Section_header(ISH, INH_32.FileHeader.NumberOfSections);

			printf("Press any key to continue...");
			getch();
			system("cls");
			break;
		}
		case 5:
		{
			free(dos_header_data);
			free(nt_header_data);
			free(section_header_data);
			
			if (flag == 1)
				free(ISH);

			if (fp != NULL)
				fclose(fp);

			return 0;
		}
		}
	}
	return 0;
}