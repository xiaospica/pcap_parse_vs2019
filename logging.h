/*
 * @Author: richard.xiao richardshawxw@gmail.com
 * @Date: 2022-05-21 20:23:41
 * @LastEditors: richard.xiao richardshawxw@gmail.com
 * @LastEditTime: 2022-05-22 11:29:48
 * @FilePath: \day06\include\logging.h
 * @Description: define logging hanlder
 *
 * Copyright (c) 2022 by richard.xiao richardshawxw@gmail.com, All Rights Reserved.
 */

#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include "spdlog/sinks/stdout_color_sinks.h"


int LogInit(const char* log_path) {

    //// create color multi threaded logger
    //auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    //console_sink->set_level(spdlog::level::debug);
    // Create a file rotating logger with 5mb size max and 10 rotated files
    size_t max_size = 1024 * 1024 * 5;
    size_t max_files = 10;
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(log_path, max_size, max_files);
    file_sink->set_level(spdlog::level::trace);

    std::vector<spdlog::sink_ptr> sinks;
    //sinks.push_back(console_sink);
    sinks.push_back(file_sink);
    auto m_logger = std::make_shared<spdlog::logger>("pcap-parse", begin(sinks), end(sinks));
    spdlog::register_logger(m_logger);
    m_logger->flush_on(spdlog::level::level_enum::warn);

    // spdlog::logger logger("pcap-parse", {console_sink, file_sink});
    // logger.set_level(spdlog::level::debug);
    // logger.info("log test");
    // logger.info("loggers can be retrieved from a global registry using the spdlog::get(logger_name)");

    return 0;
}

#endif