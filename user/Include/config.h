#ifndef CONFIG_H
#define CONFIG_H

#include <string>

#define DEFAULT_SERVER_ADDR "127.0.0.1"
#define DEFAULT_SERVER_PORT 8888
#define CONFIG_FILE_PATH "config/server.conf"

class Config {
private:
    static Config* instance;
    std::string server_addr;
    int server_port;
    bool config_loaded;

    Config();
    void load_config();
    void load_from_file(const char* config_file);
    void load_from_env();

public:
    static Config* getInstance();
    const char* get_server_addr();
    int get_server_port();
    void set_server_addr(const char* addr);
    void set_server_port(int port);
    void reload_config();
};

// C-style interface for easy integration with existing code
extern "C" {
    const char* get_server_addr();
    int get_server_port();
    void set_server_config(const char* addr, int port);
}

#endif