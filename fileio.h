/*
 * @Author: richard.xiao richardshawxw@gmail.com
 * @Date: 2022-05-21 17:37:19
 * @LastEditors: richard.xiao richardshawxw@gmail.com
 * @LastEditTime: 2022-05-22 14:59:24
 * @FilePath: \pcap_parse\include\fileio.h
 * @Description: file mapping io
 *
 * Copyright (c) 2022 by richard.xiao richardshawxw@gmail.com, All Rights Reserved.
 */

#ifndef _FILEIO_H_
#define _FILEIO_H_

#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <windows.h>

#include "protocol_format.h"

 // file mapping err
enum FileMappingErr {
    kFileMappingSucc = 0,
    kCreateFileAErr = -1,
    kCreateFileASucc = 1,
    kCreateFileMappingErr = -2,
    kCreateFileMappingSucc = 2,
    kMapViewOfFileErr = -3,
    kMapViewOfFileSucc = 3
};

// defile file mapping io class
class FileIO
{
private:
    const char* file_path = NULL; // file path
    HANDLE h_map = NULL;
    HANDLE h_file = NULL;
    struct stat file_stat;
public:
    spdlog::logger logger = *(spdlog::get("pcap-parse"));
    uint32_t file_size = 0; // file length
    char* file_pointer = NULL;
    FileIO(const char*);
    ~FileIO();
    // create file
    FileMappingErr createFile(void);
    // create fileA
    FileMappingErr createFileA(void);
    // create file mapping
    FileMappingErr createFileMapping(void);
    // map view of file
    FileMappingErr createMapViewOfFile(void);
};


#endif