#include "config.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <glog/logging.h>

Config* Config::instance = nullptr;

Config::Config() : server_addr(DEFAULT_SERVER_ADDR), server_port(DEFAULT_SERVER_PORT), config_loaded(false) {
    load_config();
}

Config* Config::getInstance() {
    static Config inst;
    instance = &inst;
    return instance;
}

void Config::load_config() {
    if (config_loaded) return;
    
    load_from_file(CONFIG_FILE_PATH);
    load_from_env();
    
    config_loaded = true;
    LOG(INFO) << "Config loaded - Server: " << server_addr << ":" << server_port;
}

void Config::load_from_file(const char* config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        LOG(WARNING) << "Config file not found: " << config_file << ", using defaults";
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;
        
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        
        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        if (key == "SERVER_ADDR") {
            server_addr = value;
        } else if (key == "SERVER_PORT") {
            server_port = std::stoi(value);
        }
    }
    
    file.close();
    LOG(INFO) << "Config loaded from file: " << config_file;
}

void Config::load_from_env() {
    const char* env_addr = std::getenv("EXPIRE_LA_SERVER_ADDR");
    if (env_addr) {
        server_addr = env_addr;
        LOG(INFO) << "Server address set from environment: " << server_addr;
    }
    
    const char* env_port = std::getenv("EXPIRE_LA_SERVER_PORT");
    if (env_port) {
        server_port = std::atoi(env_port);
        LOG(INFO) << "Server port set from environment: " << server_port;
    }
}

const char* Config::get_server_addr() {
    return server_addr.c_str();
}

int Config::get_server_port() {
    return server_port;
}

void Config::set_server_addr(const char* addr) {
    server_addr = addr;
}

void Config::set_server_port(int port) {
    server_port = port;
}

void Config::reload_config() {
    config_loaded = false;
    load_config();
}

extern "C" {
    const char* get_server_addr() {
        return Config::getInstance()->get_server_addr();
    }
    
    int get_server_port() {
        return Config::getInstance()->get_server_port();
    }
    
    void set_server_config(const char* addr, int port) {
        Config* config = Config::getInstance();
        config->set_server_addr(addr);
        config->set_server_port(port);
    }
}