/*
 * @Author: richard.xiao richardshawxw@gmail.com
 * @Date: 2022-05-21 17:37:25
 * @LastEditors: richard.xiao richardshawxw@gmail.com
 * @LastEditTime: 2022-05-22 15:48:08
 * @FilePath: \pcap_parse\src\fileio.cpp
 * @Description: implement of file mapping io
 *
 * Copyright (c) 2022 by richard.xiao richardshawxw@gmail.com, All Rights Reserved.
 */

#include "fileio.h"


FileIO::FileIO(const char* path)
{
    file_path = path;
    // read file length
    stat(file_path, &file_stat);
    file_size = file_stat.st_size;
}

FileIO::~FileIO()
{

    UnmapViewOfFile(file_pointer);
    CloseHandle(h_map);
    CloseHandle(h_file);

}

FileMappingErr FileIO::createFile(void) {

    if (this->createFileA() != kCreateFileASucc) {
        return kCreateFileAErr;
    }
    if (this->createFileMapping() != kCreateFileMappingSucc) {
        return kCreateFileMappingErr;
    }
    if (this->createMapViewOfFile() != kMapViewOfFileSucc) {
        return kMapViewOfFileErr;
    }
    return kCreateFileMappingSucc;
}

FileMappingErr FileIO::createFileA(void) {

    if (file_path != NULL && strlen(file_path) != 0) {
        h_file = CreateFileA(file_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (h_file == INVALID_HANDLE_VALUE) {
            logger.error("CreateFileA: {}", GetLastError());
            //ErrorExit((LPTSTR)"CreateFile");
            return kCreateFileAErr;
        }
        logger.info("CreateFileA successfully");
        return kCreateFileASucc;
    }
    else {
        logger.error("CreateFileA enter failed, {}", strlen(file_path));
        return kCreateFileAErr;
    }

}

FileMappingErr FileIO::createFileMapping(void) {

    h_map = CreateFileMapping(h_file,
        NULL,
        PAGE_READWRITE,
        0,
        file_size,
        NULL
    );
    if (!h_map) {
        logger.error("CreateFileMapping {}", GetLastError());
        //ErrorExit((LPTSTR)"CreateFileMapping");
        CloseHandle(h_file);
        return kCreateFileMappingErr;
    }
    logger.info("CreateFileMapping successfully");
    return kCreateFileMappingSucc;

}

FileMappingErr FileIO::createMapViewOfFile(void) {

    file_pointer = (char*)MapViewOfFile(h_map,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        file_size);
    if (!file_pointer) {
        logger.error("MapViewOfFile: {}", GetLastError());
        CloseHandle(h_map);
        CloseHandle(h_file);
        return kMapViewOfFileErr;
    }
    logger.info("createMapViewOfFile successfully");
    return kMapViewOfFileSucc;

}