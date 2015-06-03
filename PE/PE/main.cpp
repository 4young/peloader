#include <windows.h>
#include <iostream>
#include <WinNt.h>
#include <fstream>
#include <vector>
#include <string>


#define RALIGN(dwToAlign, dwAlignOn) ((dwToAlign % dwAlignOn == 0) ? dwToAlign : dwToAlign - (dwToAlign % dwAlignOn) + dwAlignOn)
#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)

using namespace std;
#define RVATOVA( base, offset )(((DWORD)(base) + (DWORD)(offset))) 
DWORD Rva2Offset(DWORD dwRva, PIMAGE_SECTION_HEADER dwSectionRva, USHORT uNumberOfSections)
{
	for (USHORT i = 0; i<uNumberOfSections; i++)
	{
		if (dwRva >= dwSectionRva->VirtualAddress)
		{
			if (dwRva < dwSectionRva->VirtualAddress + dwSectionRva->Misc.VirtualSize)
			{
				return (DWORD)(dwRva - dwSectionRva->VirtualAddress + dwSectionRva->PointerToRawData);
			}
		}
		dwSectionRva++;
	}
	return (DWORD)-1;
}

int main(void)
{
	FILE * pFile;
	DWORD lSize;
	char * buffer;
	size_t result;
	USHORT uNumberOfSections;
	DWORD  dwImportTableVirtualAddress;
	DWORD  dwImportTableVirtualSize;
	PIMAGE_DATA_DIRECTORY pimage_data_directory;

	PIMAGE_IMPORT_DESCRIPTOR pimage_import_desciptor;
	PIMAGE_SECTION_HEADER pimage_import_section_header;
	PIMAGE_THUNK_DATA pimage_thunk_data;
	PIMAGE_THUNK_DATA pimage_thunk_data1;
	PIMAGE_IMPORT_BY_NAME pimage_import_by_name;
	PIMAGE_IMPORT_BY_NAME pimage_import_by_address;
	PIMAGE_SECTION_HEADER pimage_section_header;
	pFile = fopen ( "test.exe" , "rb" );
	if (pFile==NULL) {fputs ("File error",stderr); exit (1);}

	// obtain file size:
	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);

	// allocate memory to contain the whole file:
	buffer = (char*) malloc (sizeof(char)*lSize);
	if (buffer == NULL) {fputs ("Memory error",stderr); exit (2);}

	// copy the file into the buffer:
	result = fread (buffer,1,lSize,pFile);
	if (result != lSize) {fputs ("Reading error",stderr); exit (3);}


	cout << "[*] Init headers " << endl;
	cout << "IMAGE_DOS_HEADER:" << endl;
	
	 
	//DOS заголовок
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cout << "    -DOS signature mismatch!" << endl;
	}
	//PE заголовок
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)&buffer[idh->e_lfanew];//смещение на 0x40 до заголовка PE

	cout << "    -Machine: " << std::hex << inh->FileHeader.Machine << endl;
	cout << "    -NumberOfSections: " << inh->FileHeader.NumberOfSections << endl;

	cout << "\n" << "IMAGE_FILE_HEADER:" << endl;

	IMAGE_NT_HEADERS *pPEHeader;
	pPEHeader = (IMAGE_NT_HEADERS*)&buffer[idh->e_lfanew];
	IMAGE_FILE_HEADER FileHeader;
	FileHeader = (IMAGE_FILE_HEADER)pPEHeader->FileHeader;
	cout << "    -SizeOfOptionalHeader: " << FileHeader.SizeOfOptionalHeader << endl;

	cout << "\n" << "IMAGE_OPTIONAL_HEADER32:" << endl;

	IMAGE_OPTIONAL_HEADER32 ioh = (IMAGE_OPTIONAL_HEADER32)pPEHeader->OptionalHeader;
	cout << "    -Magic: " << ioh.Magic << endl;
	cout << "    -FileAligment: " << ioh.FileAlignment << endl;
	cout << "    -ImageBase: " << ioh.ImageBase << endl;
	cout << "    -SizeOfImage: " << ioh.SizeOfImage << endl;
	cout << "    -SizeOfHeaders: " << ioh.SizeOfHeaders << endl;
	cout << "    -NumberOfRvaAndSizes: " << ioh.NumberOfRvaAndSizes << endl;
	cout << "    -DataDirectory: " << ioh.DataDirectory << endl;

	LPBYTE memory;
	memory = (LPBYTE)VirtualAlloc(NULL,
		pPEHeader->OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
		);

	memcpy_s(memory, pPEHeader->OptionalHeader.SizeOfImage, &idh->e_magic, ioh.SizeOfHeaders);

	cout << "[*] Init sections " << endl;
	IMAGE_SECTION_HEADER *ios = (IMAGE_SECTION_HEADER *)((BYTE *)&pPEHeader->OptionalHeader + FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < FileHeader.NumberOfSections; ++i)
	{
		cout << "\n\n" << "    -Name: " << ios->Name << endl;
		cout << "    -PointerToRawData: " << ios->PointerToRawData << endl;
		cout << "    -NumberOfLinenumbers: " << ios->NumberOfLinenumbers << endl;
		cout << "    -VirtualAddress: " << ios->VirtualAddress << endl;
		cout << "    -PointerToRelocations" << ios->PointerToRelocations << endl;
		DWORD VirtualSize = (i == FileHeader.NumberOfSections - 1) ?
			(ioh.SizeOfImage - ios->VirtualAddress)
			: (ios + 1)->VirtualAddress - ios->VirtualAddress;
		LPVOID va = (LPVOID)(memory + ios->VirtualAddress);
		DWORD virtual_size_aligned = ALIGN_UP(VirtualSize, ioh.SectionAlignment);
		memcpy_s(va, ios->SizeOfRawData, buffer+ios->PointerToRawData, ios->SizeOfRawData);
		
		ios++;
	}

	cout << "\n" << "[*] Init Import table " << endl;


	
	if (pPEHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		uNumberOfSections = pPEHeader->FileHeader.NumberOfSections;
	}
	else return -1;
	

	pimage_data_directory = ioh.DataDirectory;
	++pimage_data_directory;
	dwImportTableVirtualAddress = pimage_data_directory->VirtualAddress;
	dwImportTableVirtualSize = pimage_data_directory->Size;
	

	pimage_section_header = (PIMAGE_SECTION_HEADER)((DWORD)buffer + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	pimage_import_section_header = pimage_section_header;
	
	if (dwImportTableVirtualSize != 0)
	{
		pimage_import_desciptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)buffer + Rva2Offset(dwImportTableVirtualAddress, pimage_import_section_header, uNumberOfSections));
		printf("\nIMAGE_IMPORT_DESCRIPTOR\n");
		while (pimage_import_desciptor->Name != NULL)
		{
			printf("Name                               ");
			printf("%s\n", (char *)((DWORD)buffer + Rva2Offset(pimage_import_desciptor->Name, pimage_import_section_header, uNumberOfSections)));
			char* LibName = (char *)((DWORD)buffer + Rva2Offset(pimage_import_desciptor->Name, pimage_import_section_header, uNumberOfSections));
			cout << "[*] Fixing image import descriptor for " << LibName << endl;
			HINSTANCE hinstLib; 
			hinstLib =   LoadLibraryA(LibName);//<--------GET HINSTANCE dll 
			DWORD NumError = GetLastError();

			if (pimage_import_desciptor->OriginalFirstThunk != 0)
			{
				pimage_thunk_data = (PIMAGE_THUNK_DATA)((DWORD)buffer + Rva2Offset(pimage_import_desciptor->OriginalFirstThunk, pimage_import_section_header, uNumberOfSections));
				pimage_thunk_data1 = (PIMAGE_THUNK_DATA)((DWORD)buffer + Rva2Offset(pimage_import_desciptor->FirstThunk, pimage_import_section_header, uNumberOfSections));
			}
			else
			{
				pimage_thunk_data = (PIMAGE_THUNK_DATA)((DWORD)buffer + Rva2Offset(pimage_import_desciptor->FirstThunk, pimage_import_section_header, uNumberOfSections));
				pimage_thunk_data1 = (PIMAGE_THUNK_DATA)((DWORD)buffer + Rva2Offset(pimage_import_desciptor->FirstThunk, pimage_import_section_header, uNumberOfSections));
			}
			printf("\nHint                               Function\n");
			while (pimage_thunk_data->u1.Ordinal != 0)
			{
				pimage_import_by_name = (PIMAGE_IMPORT_BY_NAME)((DWORD)buffer + Rva2Offset(pimage_thunk_data->u1.Function, pimage_import_section_header, uNumberOfSections));
				pimage_import_by_address = (PIMAGE_IMPORT_BY_NAME)((DWORD)buffer + Rva2Offset(pimage_thunk_data1->u1.AddressOfData,pimage_import_section_header, uNumberOfSections));
				
				if (pimage_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				{
					printf("Hint                               %08lX\n", pimage_thunk_data->u1.Ordinal - IMAGE_ORDINAL_FLAG32);
				}
				else
				{
					cout << "________________________________________________________________________________" << endl;
					printf("%08lX                           %s\n", pimage_import_by_name->Hint, pimage_import_by_name->Name);
					LPCSTR FuncName = (LPCSTR)pimage_import_by_name->Name;
					DWORD_PTR Addressfun = (DWORD_PTR )GetProcAddress(hinstLib, (LPCSTR)pimage_import_by_name->Name); //<--------GET Function address
					DWORD_PTR OldAddress = pimage_thunk_data1->u1.AddressOfData;
					pimage_thunk_data1->u1.AddressOfData = Addressfun;
					cout <<"FirstThunkAddress:" << pimage_import_by_address->Hint;
					cout << "\n" << "[*] Updated FirstThunk from " << OldAddress << " to " << Addressfun <<" \n\n " << endl;
					cout << "_______________________________________________________________________________" << endl;
				}
				pimage_thunk_data++;
				pimage_thunk_data1++;
			}
			printf("\n");
			pimage_import_desciptor++;
		}
	}
	else
	{
		printf("No Import Table!\n");
	}
	cout << "\n" << "[*] Init Relocation table " << endl;
	IN PVOID base = 0;
	base = (PVOID) ioh.ImageBase;
	if( !ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress )
		{
			
			printf("Decided to load at different base, but no relocs present\n");
			VirtualFree( base, ioh.SizeOfImage, MEM_DECOMMIT );
			VirtualFree( base, ioh.SizeOfImage, MEM_RELEASE );
			return NULL;
		}
	PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)(ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress+ioh.ImageBase);

	return 0;
}