/*
    Copyright (C) 2015  maldevel - maldevel@mail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <stdbool.h>

bool FileExists(const char* filepath);
DWORD VirtualAddress2FileOffset(const DWORD address, const PIMAGE_DOS_HEADER dosHeader, const IMAGE_FILE_HEADER _header, const BYTE* fileBuffer);

int main(int argc, char** argv)
{
    "This program comes with ABSOLUTELY NO WARRANTY.\n"
    "This is free software, and you are welcome to redistribute it\n"
    "under certain conditions. Please Read GPLv3.\n\n");

	HANDLE _file;

	PIMAGE_DOS_HEADER _dosHeader;
	PIMAGE_NT_HEADERS _ntHeader;
	IMAGE_FILE_HEADER _header;
	IMAGE_OPTIONAL_HEADER _opHeader;
	PIMAGE_SECTION_HEADER _sectionHeader;

	int i = 0;
	UINT ii = 0;
	UINT iii = 0;

	DWORD _size;
	DWORD _byteread;
	PVOID _fileBuffer;

	PIMAGE_IMPORT_DESCRIPTOR _importDescriptor;
	PIMAGE_EXPORT_DIRECTORY _exportDirectory;

	PDWORD _addrOfFunctions;
	PWORD _nameOrdinals;
	PDWORD _names;

	if (argc >1){


		/*
		 * Check if file exists.
		 *
		 */
		if(!FileExists(argv[1])){
			printf("File %s doesn't exist.\n", argv[1]);
			return -1;
		}


		/*
		 * Open file.
		 *
		 * CreateFile - Creates or opens a file or I/O device.
		 * The most commonly used I/O devices are as follows:
		 * file, file stream, directory, physical disk, volume,
		 * console buffer, tape drive, communications resource,
		 * mailslot, and pipe. The function returns a handle that
		 * can be used to access the file or device for various
		 * types of I/O depending on the file or device and the
		 * flags and attributes specified.
		 *
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858%28v=vs.85%29.aspx
		 *
		 */
		_file = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(_file == INVALID_HANDLE_VALUE){
			printf("Failed to open file %s. Error Code %lu.\n", argv[1], GetLastError());
			return -1;
		}


		/*
		 * Read file.
		 *
		 * ReadFile - Reads data from the specified file or input/output
		 * (I/O) device. Reads occur at the position specified by the
		 * file pointer if supported by the device.
		 *
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467%28v=vs.85%29.aspx
		 *
		 * GetFileSize - Retrieves the size of the specified file, in bytes.
		 *
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa364955%28v=vs.85%29.aspx
		 *
		 * VirtualAlloc - Reserves or commits a region of pages in the
		 * virtual address space of the calling process. Memory allocated
		 * by this function is automatically initialized to zero,
		 * unless MEM_RESET is specified.
		 *
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887%28v=vs.85%29.aspx
		 *
		 * VirtualFree - Releases, decommits, or releases and decommits
		 * a region of pages within the virtual address space of the
		 * calling process.
		 *
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa366892%28v=vs.85%29.aspx
		 *
		 */
		_size = GetFileSize(_file, NULL);
		_fileBuffer = VirtualAlloc(NULL, _size, MEM_COMMIT, PAGE_READWRITE);
		if(ReadFile(_file, _fileBuffer, _size, &_byteread, NULL) == 0){
			printf("Failed to read file %s. Error Code %lu.\n", argv[1], GetLastError());
			if(_fileBuffer) VirtualFree(_fileBuffer, _size, MEM_DECOMMIT);
			return -1;
		}


		/*
		 * Close file handle.
		 *
		 * CloseHandle - Closes an open object handle.
		 *
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211%28v=vs.85%29.aspx
		 *
		 */
		CloseHandle(_file);


		printf("------------------------------------------------------------------------------------------\n\n");
		printf("---------------------------------Dumping file information---------------------------------\n\n");
		printf("File name: \t\t\t\t%s\n", argv[1]);


		/*
		 * Print file size.
		 *
		 */
		printf("File size: \t\t\t\t%lu bytes\n\n", _size);//_file_size.QuadPart);



		/*
		 * Get DOS and NT headers bases.
		 *
		 * PIMAGE_DOS_HEADER
		 *
		 * http://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html
		 *
		 * IMAGE_NT_HEADERS - Represents the PE header format.
		 *
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms680336%28v=vs.85%29.aspx
		 *
		 */
		_dosHeader = 	(PIMAGE_DOS_HEADER)	_fileBuffer;
		_ntHeader  = 	(PIMAGE_NT_HEADERS)(_fileBuffer + _dosHeader->e_lfanew);//(PIMAGE_NT_HEADERS)((DWORD)(_dosHeader) + (_dosHeader->e_lfanew));


		/*
		 * Check if executable file is a valid DOS-PE file.
		 *
		 */
		if(_dosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
				_ntHeader->Signature == IMAGE_NT_SIGNATURE){


			/*
			 * Dump DOS header information.
			 *
			 */
			printf("----------------------------------DOS Header Information----------------------------------\n\n");
			printf("Magic number: \t\t\t\t%#x (%s)\n", 				_dosHeader->e_magic, _dosHeader->e_magic == 0x5a4d ? "MZ" : "-");
			printf("Bytes on last page of file: \t\t%d\n", 			_dosHeader->e_cblp		);
			printf("Pages in file: \t\t\t\t%#x\n", 					_dosHeader->e_cp		);
			printf("Relocations: \t\t\t\t%#x\n",					_dosHeader->e_crlc		);
			printf("Size of header in paragraphs: \t\t%#x\n", 		_dosHeader->e_cparhdr	);
			printf("Minimum extra paragraphs needed: \t%#x\n", 		_dosHeader->e_minalloc	);
			printf("Maximum extra paragraphs needed: \t%#x\n",		_dosHeader->e_maxalloc	);
			printf("Initial (relative) SS value: \t\t%#x\n", 		_dosHeader->e_ss		);
			printf("Initial SP value: \t\t\t%#x\n",					_dosHeader->e_sp		);
			printf("Checksum: \t\t\t\t%#x\n", 						_dosHeader->e_csum		);
			printf("Initial IP value: \t\t\t%#x\n", 				_dosHeader->e_ip		);
			printf("Initial (relative) CS value: \t\t%#x\n", 		_dosHeader->e_cs		);
			printf("File address of relocation table: \t%#x\n",		_dosHeader->e_lfarlc	);
			printf("Overlay number: \t\t\t%#x\n", 					_dosHeader->e_ovno		);
			printf("OEM identifier (for e_oeminfo): \t%#x\n", 		_dosHeader->e_oemid		);
			printf("OEM information; e_oemid specific: \t%#x\n",	_dosHeader->e_oeminfo	);
			printf("File address of new exe header: \t%#lx\n\n",	_dosHeader->e_lfanew	);


			/*
			 * Get Image File Header (COFF).
			 *
			 * IMAGE_FILE_HEADER - Represents the COFF header format.
			 *
			 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313%28v=vs.85%29.aspx
			 *
			 */
			_header = _ntHeader->FileHeader;


			/*
			 * Dump NT header information.
			 *
			 */
			printf("---------------------------------- NT Header Information----------------------------------\n\n");
			printf("Signature: \t\t\t\t%#lx (%s)\n", 				_ntHeader->Signature, "PE"		);
			printf("Computer architecture type: ");
			switch(_header.Machine){
			case IMAGE_FILE_MACHINE_I386:
				printf("\t\tx86\n");
				break;
			case IMAGE_FILE_MACHINE_IA64:
				printf("\t\tIntel Itanium\n");
				break;
			case IMAGE_FILE_MACHINE_AMD64:
				printf("\t\tx64\n");
				break;
			}
			printf("Number of sections: \t\t\t%#x\n", 				_header.NumberOfSections		);
			printf("Timestamp: \t\t\t\t%lu\n", 						_header.TimeDateStamp			);
			printf("Symbol table offset: \t\t\t%#lx\n", 			_header.PointerToSymbolTable	);
			printf("Number of symbols: \t\t\t%#lx\n", 				_header.NumberOfSymbols			);
			printf("Size of optional headers: \t\t%#x\n", 			_header.SizeOfOptionalHeader	);
			printf("Image characteristics: ");
			if((_header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
				printf("\t\t\tThe file is executable.\n");
			if((_header.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) == IMAGE_FILE_LARGE_ADDRESS_AWARE)
				printf("\t\t\tThe application can handle addresses larger than 2 GB.\n");
			if((_header.Characteristics & IMAGE_FILE_SYSTEM) == IMAGE_FILE_SYSTEM)
				printf("\t\t\tThe image is a system file.\n");
			if((_header.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
				printf("\t\t\tThe image is a DLL file.\n");
			printf("\n");


			/*
			 * Get Image Optional Header.
			 *
			 * IMAGE_OPTIONAL_HEADER - Represents the optional header format.
			 *
			 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339%28v=vs.85%29.aspx
			 *
			 */
			_opHeader = _ntHeader->OptionalHeader;


			/*
			 * Dump PE Optional header information.
			 *
			 */
			printf("------------------------------PE Optional Header Information------------------------------\n\n");
			printf("Image file state: \t\t\t\t\t%#x \t(%s)\n", 								_opHeader.Magic, _opHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE64" : "PE32" );
			printf("Major Linker Version: \t\t\t\t\t%#x \t(%d)\n",							_opHeader.MajorLinkerVersion, 			_opHeader.MajorLinkerVersion					);
			printf("Minor Linker Version: \t\t\t\t\t%#x \t(%d)\n",							_opHeader.MinorLinkerVersion, 			_opHeader.MinorLinkerVersion					);
			printf("Size of code section(.text): \t\t\t\t%lu \tbytes\n",					_opHeader.SizeOfCode															);
			printf("Size of initialized data section: \t\t\t%lu \tbytes\n",					_opHeader.SizeOfInitializedData													);
			printf("Size of uninitialized data section: \t\t\t%lu \tbytes\n",				_opHeader.SizeOfUninitializedData												);
			printf("Address of entry point: \t\t\t\t%#lx\n",								_opHeader.AddressOfEntryPoint													);
			printf("Base address of code section: \t\t\t\t%#lx\n",							_opHeader.BaseOfCode															);
			printf("Base address of data section: \t\t\t\t%#lx\n",							_opHeader.BaseOfData															);
			printf("Base address of image in memory: \t\t\t%#lx\n",							_opHeader.ImageBase																);
			printf("Sections alignment in memory (bytes): \t\t\t%#lx\n", 					_opHeader.SectionAlignment														);
			printf("Raw data of sections alignment in image file (bytes): \t%#lx\n", 		_opHeader.FileAlignment															);
			printf("OS major version required: \t\t\t\t%#x \t(%d)\n",						_opHeader.MajorOperatingSystemVersion, 	_opHeader.MajorOperatingSystemVersion 	);
			printf("OS minor version required: \t\t\t\t%#x \t(%d)\n",						_opHeader.MinorOperatingSystemVersion, 	_opHeader.MinorOperatingSystemVersion 	);
			printf("Image major version number: \t\t\t\t%#x \t(%d)\n",						_opHeader.MajorImageVersion, 			_opHeader.MajorImageVersion 			);
			printf("Image minor version number: \t\t\t\t%#x \t(%d)\n",						_opHeader.MinorImageVersion, 			_opHeader.MinorImageVersion			 	);
			printf("Subsystem major version number: \t\t\t%#x \t(%d)\n",					_opHeader.MajorSubsystemVersion, 		_opHeader.MajorSubsystemVersion		 	);
			printf("Subsystem minor version number: \t\t\t%#x \t(%d)\n",					_opHeader.MinorSubsystemVersion, 		_opHeader.MinorSubsystemVersion		 	);
			printf("Image size: \t\t\t\t\t\t%lu \tbytes\n",									_opHeader.SizeOfImage															);
			printf("Size of headers: \t\t\t\t\t%lu \tbytes\n",								_opHeader.SizeOfHeaders															);
			printf("Image file checksum: \t\t\t\t\t%#lx\n",									_opHeader.CheckSum																);
			printf("Subsystem: \t\t\t\t\t\t%#x (",											_opHeader.Subsystem																);
			switch(_opHeader.Subsystem){
			case IMAGE_SUBSYSTEM_NATIVE:
				printf("Device driver - Native system process)\n");
				break;
			case IMAGE_SUBSYSTEM_WINDOWS_GUI:
				printf("Windows GUI)\n");
				break;
			case IMAGE_SUBSYSTEM_WINDOWS_CUI:
				printf("Windows CUI)\n");
				break;
			case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
				printf("Windows CE)\n");
				break;
			}
			printf("Dll characteristics: \t\t\t\t\t%#x\n",									_opHeader.DllCharacteristics					);
			printf("Number of bytes reserved for stack: \t\t\t%lu bytes\n",					_opHeader.SizeOfStackReserve					);
			printf("Number of bytes to commit for stack: \t\t\t%lu bytes\n",				_opHeader.SizeOfStackCommit						);
			printf("Number of bytes to reserve for local heap: \t\t%lu bytes\n",			_opHeader.SizeOfHeapReserve						);
			printf("Number of bytes to commit for local heap: \t\t%lu bytes\n",				_opHeader.SizeOfHeapCommit						);
			printf("Number of directory entries: \t\t\t\t%lu\n\n",							_opHeader.NumberOfRvaAndSizes					);


			/*
			 * Get Image Data Directories.
			 *
			 * IMAGE_DATA_DIRECTORY - Represents the data directory.
			 *
			 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms680305%28v=vs.85%29.aspx
			 *
			 */


			/*
			 * Dump Image Data Directories.
			 *
			 */
			printf("----------------------------------Image Data Directories----------------------------------\n\n");
			for(i = 0; i < _opHeader.NumberOfRvaAndSizes; i++)
				printf("Directory No. %d: \t\t\t\t\t%#lx (%lu bytes)\n", i, _opHeader.DataDirectory[i].VirtualAddress, _opHeader.DataDirectory[i].Size 	);
			printf("\n");


			/*
			 * Get Image Section Header.
			 *
			 * IMAGE_SECTION_HEADER - Represents the image section header format.
			 *
			 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341%28v=vs.85%29.aspx
			 *
			 */
			_sectionHeader = (PIMAGE_SECTION_HEADER)(_ntHeader);


			/*
			 * Dump Image Section Header.
			 *
			 */
			printf("-----------------------------------Image Section Header-----------------------------------\n\n");
			for (i = 0; i < _header.NumberOfSections;i++, _sectionHeader++){
				printf("Section name: \t\t\t\t\t\t%s\n", 							_sectionHeader->Name						);
				printf("File Address: \t\t\t\t\t\t%#lx\n", 							_sectionHeader->Misc.PhysicalAddress		);
				printf("Section size in memory: \t\t\t\t%lu bytes\n", 				_sectionHeader->Misc.VirtualSize			);
				printf("Virtual Address: \t\t\t\t\t%#lx\n", 						_sectionHeader->VirtualAddress				);
				printf("Size of initialized data on disk: \t\t\t%lu bytes\n",		_sectionHeader->SizeOfRawData				);
				printf("Pointer to raw data: \t\t\t\t\t%#lx\n",						_sectionHeader->PointerToRawData			);
				printf("Pointer to relocations: \t\t\t\t%#lx\n",					_sectionHeader->PointerToRelocations		);
				printf("Pointer to line numbers: \t\t\t\t%#lx\n",					_sectionHeader->PointerToLinenumbers		);
				printf("Number of relocation entries: \t\t\t\t%#x\n",				_sectionHeader->NumberOfRelocations			);
				printf("Number of line number entries: \t\t\t\t%#x\n",				_sectionHeader->NumberOfLinenumbers			);
				printf("Image characteristics: ");
				if((_sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE)
					printf("\t\t\t\t\tThe section contains executable code.\n");
				if((_sectionHeader->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == IMAGE_SCN_CNT_INITIALIZED_DATA)
					printf("\t\t\t\t\tThe section contains initialized data.\n");
				if((_sectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA)
					printf("\t\t\t\t\tThe section contains uninitialized data.\n");
				if((_sectionHeader->Characteristics & IMAGE_SCN_LNK_INFO) == IMAGE_SCN_LNK_INFO)
					printf("\t\t\t\t\tThe section contains comments or other information.\n");
				if((_sectionHeader->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
					printf("\t\t\t\t\tThe section can be shared in memory.\n");
				if((_sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
					printf("\t\t\t\t\tThe section can be executed as code.\n");
				if((_sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ)
					printf("\t\t\t\t\tThe section can be read.\n");
				if((_sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE)
					printf("\t\t\t\t\tThe section can be written to.\n");

				printf("\n\n");
			}


			/*
			 * Get Import Table.
			 *
			 */
			if (IMAGE_DIRECTORY_ENTRY_IMPORT >= _opHeader.NumberOfRvaAndSizes ||
					_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
				printf("Image doesn't have an import table.\n");
			else{
				_importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)VirtualAddress2FileOffset(_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
						_dosHeader, _header, _fileBuffer);

				if(_importDescriptor){

					/*
					 * Dump Imports.
					 *
					 */
					printf("-----------------------------------------IMPORTS-----------------------------------------\n\n");
					while(_importDescriptor->Name){
						char* _name = (char*)VirtualAddress2FileOffset(_importDescriptor->Name, _dosHeader, _header, _fileBuffer);
						printf("DLL Name: \t\t\t\t\t\t%s\n",				_name													);
						printf("Characteristics: \t\t\t\t\t%#lx\n",			_importDescriptor->Characteristics						);
						printf("First Thunk: \t\t\t\t\t\t%#lx\n",			_importDescriptor->FirstThunk							);
						printf("Forwarder Chain: \t\t\t\t\t%#lx\n",			_importDescriptor->ForwarderChain						);
						printf("Original First Thunk: \t\t\t\t\t%#lx\n",	_importDescriptor->OriginalFirstThunk					);
						printf("TimeDateStamp: \t\t\t\t\t\t%lu\n\n",		_importDescriptor->TimeDateStamp						);


						/*
						 * Dump Import Address Table.
						 *
						 */
						PIMAGE_THUNK_DATA _IAT = (PIMAGE_THUNK_DATA)VirtualAddress2FileOffset(_importDescriptor->OriginalFirstThunk, _dosHeader, _header, _fileBuffer);


						/*
						 * Dump imported functions
						 *
						 */
						printf("-----------------------------------IMPORTED FUNCTIONS------------------------------------\n\n");
						while (_IAT->u1.AddressOfData){

							if (IMAGE_SNAP_BY_ORDINAL(_IAT->u1.Ordinal))
								printf("Ordinal: \t\t\t\t\t\t%#lx\n",						IMAGE_ORDINAL(_IAT->u1.Ordinal)							);
							else{
								PIMAGE_IMPORT_BY_NAME _Import = (PIMAGE_IMPORT_BY_NAME)VirtualAddress2FileOffset(_IAT->u1.AddressOfData,
										_dosHeader, _header, _fileBuffer);
								printf("Function Name (Hint): \t\t\t\t\t%s \t(%#x)\n",		_Import->Name, _Import->Hint							);
							}

							_IAT++;
						}

						_importDescriptor++;
						printf("\n---------------------end of %s information---------------------\n\n", _name);
					}
				}
			}

			/*
			 * Get Export Table.
			 *
			 */
			if (IMAGE_DIRECTORY_ENTRY_EXPORT >= _opHeader.NumberOfRvaAndSizes ||
					_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
				printf("Image doesn't have an export table.\n");
			else{
				_exportDirectory = (PIMAGE_EXPORT_DIRECTORY)VirtualAddress2FileOffset(_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
									_dosHeader, _header, _fileBuffer);

				if(_exportDirectory){

					/*
					 * Dump Exports.
					 *
					 */
					printf("-----------------------------------------EXPORTS-----------------------------------------\n\n");
					char* _name = (char*)VirtualAddress2FileOffset(_exportDirectory->Name, _dosHeader, _header, _fileBuffer);
					printf("DLL Name: \t\t\t\t\t\t%s\n",							_name									);
					printf("Characteristics: \t\t\t\t\t%#lx\n",						_exportDirectory->Characteristics		);
					printf("Ordinal Base: \t\t\t\t\t\t%#lx\n",						_exportDirectory->Base					);
					printf("Major Version: \t\t\t\t\t\t%d\n",						_exportDirectory->MajorVersion			);
					printf("Minor Version: \t\t\t\t\t\t%d\n",						_exportDirectory->MinorVersion			);
					printf("Exported functions: \t\t\t\t\t%lu\n",					_exportDirectory->NumberOfFunctions		);
					printf("Functions exported by name: \t\t\t\t%lu\n",				_exportDirectory->NumberOfNames			);
					printf("TimeStamp: \t\t\t\t\t\t%lu\n\n",						_exportDirectory->TimeDateStamp			);


					/*
					 * Dump exported functions.
					 *
					 */
					_addrOfFunctions = 	(PDWORD)VirtualAddress2FileOffset(_exportDirectory->AddressOfFunctions, 	_dosHeader, _header, _fileBuffer);
					_nameOrdinals = 	(PWORD)VirtualAddress2FileOffset(_exportDirectory->AddressOfNameOrdinals, 	_dosHeader, _header, _fileBuffer);
					_names = 			(PDWORD)VirtualAddress2FileOffset(_exportDirectory->AddressOfNames, 		_dosHeader, _header, _fileBuffer);


					printf("-------------------------------EXPORTED FUNCTIONS BY NAME--------------------------------\n\n");

					for (ii = 0; ii < _exportDirectory->NumberOfNames; ii++){
						//not forwarded functions
						if (_addrOfFunctions[_nameOrdinals[ii]] < _opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress ||
								_addrOfFunctions[_nameOrdinals[ii]] > _opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress +
									_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
						{
							printf("Function Name: \t\t\t\t\t\t%s\n", 			(char*)VirtualAddress2FileOffset(_names[ii], _dosHeader, _header, _fileBuffer)	);
							printf("Ordinal: \t\t\t\t\t\t%#lx\n", 				_nameOrdinals[ii] + _exportDirectory->Base										);
							printf("Relative Address: \t\t\t\t\t%#lx\n\n", 		_addrOfFunctions[_nameOrdinals[ii]]												);
						}

						//forwarded functions
						else{
							printf("Function Name: \t\t\t\t\t\t%s\n", 			(char*)VirtualAddress2FileOffset(_names[ii], _dosHeader, _header, _fileBuffer)	);
							printf("Ordinal: \t\t\t\t\t\t%#lx\n", 				_nameOrdinals[ii] + _exportDirectory->Base										);
							printf("Relative Address: \t\t\t\t\t%#lx\n", 		_addrOfFunctions[_nameOrdinals[ii]]												);
							printf("Forwarded to: \t\t\t\t\t%s\n\n", 			(char*)VirtualAddress2FileOffset(_addrOfFunctions[_nameOrdinals[ii]], _dosHeader, _header, _fileBuffer)	);
						}
					}


					printf("------------------------------EXPORTED FUNCTIONS BY ORDINAL------------------------------\n\n");
					for (ii = 0; ii < _exportDirectory->NumberOfFunctions; ii++) {
						if (_addrOfFunctions[ii] != 0) {

							for (iii = 0; iii<_exportDirectory->NumberOfNames; iii++) {
								if (_addrOfFunctions[_nameOrdinals[iii]] == _addrOfFunctions[ii])
									break;
							}

							if (iii >= _exportDirectory->NumberOfNames) {
								if (_addrOfFunctions[ii] < _sectionHeader->VirtualAddress ||
										_addrOfFunctions[ii] > _sectionHeader->VirtualAddress + _sectionHeader->Misc.VirtualSize){
									printf("Function Name: \t\t\t\t\t\tNo Name\n"										);
									printf("Ordinal: \t\t\t\t\t\t%#lx\n", 					ii + _exportDirectory->Base		);
									printf("Relative Address: \t\t\t\t\t%#lx\n\n",			_addrOfFunctions[ii]			);
								}
								//forwarded functions
								else{
									printf("Function Name: \t\t\t\t\t\tNo Name\n"										);
									printf("Ordinal: \t\t\t\t\t\t%#lx\n\n", 				ii + _exportDirectory->Base		);
									//printf("Forwarded to: \t\t\t\t\t\t%s\n\n", 			(char*)_fileBuffer + _sectionHeader->PointerToRawData + _addrOfFunctions[i] - _sectionHeader->VirtualAddress	);
								}
							}
						}
					}
				}
			}
		}
		else{
			printf("Given file %s is not a valid DOS-PE file.\n", argv[1]);
			if(_fileBuffer) VirtualFree(_fileBuffer, _size, MEM_DECOMMIT);
			return -1;
		}


		printf("-----------------------------------------------------------------------------------------\n");

	}
	else{


	}

	return EXIT_SUCCESS;
}


/*
 * Check file existence
 */
bool FileExists(const char* filepath){


	if(filepath == NULL) return false;


	/*
	 * WIN32_FILE_ATTRIBUTE_DATA - Contains attribute information
	 * for a file or directory.
	 *
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365739%28v=vs.85%29.aspx
	 *
	 */
	WIN32_FILE_ATTRIBUTE_DATA _fileinfo = {0};


	/*
	 * Retrieve file information
	 *
	 * GetFileAttributesEx - Retrieves attributes for a specified
	 * file or directory.
	 *
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa364946%28v=vs.85%29.aspx
	 *
	 */
	if (GetFileAttributesEx(filepath, GetFileExInfoStandard, &_fileinfo) == 0)
		return false;
	else
		return true;
}


/*
 * Convert given Virtual Address to file offset
 *
 */
DWORD VirtualAddress2FileOffset(const DWORD address, const PIMAGE_DOS_HEADER dosHeader, const IMAGE_FILE_HEADER _header, const BYTE* fileBuffer)
{
    WORD i = 0;
    PIMAGE_SECTION_HEADER secHeader = (PIMAGE_SECTION_HEADER)(fileBuffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    if(address == 0)
    {
    	return 0;
    }

    for(i = 0; i < _header.NumberOfSections; i++)
    {
    		if ((secHeader->VirtualAddress <= address) && (address < (secHeader->VirtualAddress + secHeader->Misc.VirtualSize)))
    			break;
    		secHeader++;
    }

    return (DWORD)(fileBuffer + secHeader->PointerToRawData + (address - secHeader->VirtualAddress));
}


