/*
 * @Author: richard.xiao richardshawxw@gmail.com
 * @Date: 2022-05-21 18:31:21
 * @LastEditors: richard.xiao richardshawxw@gmail.com
 * @LastEditTime: 2022-05-22 16:03:02
 * @FilePath: \pcap_parse\process_pcap.cpp
 * @Description: main func for processing pcap
 *
 * Copyright (c) 2022 by richard.xiao richardshawxw@gmail.com, All Rights Reserved.
 */

#include "logging.h"
#include "fileio.h"
#include "pcap_parser.h"
#include <spdlog/spdlog.h>

int main(void) {

    // init log
    LogInit("log/rotating.txt");
    spdlog::logger logger = *(spdlog::get("pcap-parse"));

    const char* pcap_path = "F:/Laptop Disk E/BaiduNetdiskDownload/知识星球_手写一个抓包软件/day08-09/day8.pcap";
    FileIO* file_io = new FileIO(pcap_path);
    FileMappingErr ret = file_io->createFile();
    if (ret != kCreateFileMappingSucc) {
        logger.error("create file mapping failed: {}", ret);
    }
    logger.info("create file mapping successfully");

    // parse pcap
    std::string packet_filter = "";
    PcapParser* pcap_parser = new PcapParser(file_io->file_pointer, file_io->file_size);
    pcap_parser->run(packet_filter);

    // close log
    spdlog::shutdown();
}