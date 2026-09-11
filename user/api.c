#include "user_config.h"
#include "ets_sys.h"
#include "osapi.h"
#include "espconn.h"
#include "mem.h"
#include "os_type.h"
#include "user_interface.h"
#include "ip_addr.h"
#include "netif.h"
#include "lwip/netif.h"
#include "eagle_lwip_getif.h"
#include "config_flash.h"
#ifdef REPEATER_MODE
#include "bridge.h"
#endif

// Helper: convert IP address to string
static void ICACHE_FLASH_ATTR ip_to_str(char *buf, uint32_t ip) {
    os_sprintf(buf, "%d.%d.%d.%d", 
               (ip >> 0) & 0xFF, (ip >> 8) & 0xFF, 
               (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

// Helper: convert MAC to string
static void ICACHE_FLASH_ATTR mac_to_str(char *buf, const uint8_t *mac) {
    os_sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Simple JSON escape - minimal for SSID/passwords
static void ICACHE_FLASH_ATTR json_escape(char *dst, const char *src, int max_len) {
    int di = 0, si = 0;
    while (src[si] && di < max_len - 2) {
        char c = src[si++];
        if (c == '"' || c == '\\') {
            dst[di++] = '\\';
        }
        dst[di++] = c;
    }
    dst[di] = '\0';
}

// GET /api/status
static void ICACHE_FLASH_ATTR api_get_status(struct espconn *pespconn) {
    char *buf = (char *)os_malloc(1024);
    if (!buf) return;
    
    struct netif *sta_netif = (struct netif *)eagle_lwip_getif(0);
    struct netif *ap_netif = (struct netif *)eagle_lwip_getif(1);
    
    // STA info
    char sta_ip[16] = "—";
    char sta_ssid[33] = "—";
    int sta_rssi = 0;
    
    if (sta_netif && wifi_station_get_connect_status() == STATION_GOT_IP) {
        ip_to_str(sta_ip, sta_netif->ip_addr.addr);
        struct station_config sta_conf;
        if (wifi_station_get_config(&sta_conf)) {
            os_memcpy(sta_ssid, sta_conf.ssid, 32);
            sta_ssid[32] = '\0';
        }
        sta_rssi = wifi_station_get_rssi();
    }
    
    // AP info
    char ap_ssid[33] = "—";
    struct softap_config ap_conf;
    if (wifi_softap_get_config(&ap_conf)) {
        os_memcpy(ap_ssid, ap_conf.ssid, 32);
        ap_ssid[32] = '\0';
    }
    
    // Clients
    struct station_info *clients = wifi_softap_get_station_info();
    int client_count = 0;
    char clients_json[512] = "";
    int clen = 0;
    
    while (clients && client_count < 8) {
        char mac[18], ip[16];
        mac_to_str(mac, clients->bssid);
        ip_to_str(ip, clients->ip.addr);
        
        if (client_count > 0) clen += os_sprintf(clients_json + clen, ",");
        clen += os_sprintf(clients_json + clen, 
                          "{\"name\":\"—\",\"ip\":\"%s\",\"mac\":\"%s\"}", ip, mac);
        
        clients = STAILQ_NEXT(clients, next);
        client_count++;
    }
    wifi_softap_free_station_info();
    
    // System info
    uint32_t uptime = (uint32_t)(system_get_time() / 1000000);
    uint32_t free_heap = system_get_free_heap_size();
    
    os_sprintf(buf, 
        "{\"sta\":{\"ssid\":\"%s\",\"ip\":\"%s\",\"rssi\":%d},"
        "\"ap\":{\"ssid\":\"%s\",\"clients\":[%s],\"secure\":%s},"
        "\"system\":{\"uptime\":%lu,\"freeHeap\":%lu,\"version\":\"%s\"}}",
        sta_ssid, sta_ip, sta_rssi,
        ap_ssid, clients_json,
        config.ap_open ? "false" : "true",
        uptime, free_heap, ESP_REPEATER_VERSION);
    
    char hdr[128];
    os_sprintf(hdr, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", os_strlen(buf));
    espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
    espconn_send(pespconn, (uint8_t *)buf, os_strlen(buf));
    os_free(buf);
}

// Scan state
static struct espconn *scan_conn = NULL;
static bool scan_pending = false;

// GET /api/scan
static void ICACHE_FLASH_ATTR api_get_scan(struct espconn *pespconn) {
    if (scan_pending) {
        // Already scanning - send 503
        char hdr[] = "HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Scan in progress\"}";
        espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
        return;
    }
    
    scan_conn = pespconn;
    scan_pending = true;
    wifi_station_scan(NULL, api_scan_done);
}

void ICACHE_FLASH_ATTR api_scan_done(void *arg, STATUS status) {
    if (!scan_pending || !scan_conn) {
        scan_pending = false;
        scan_conn = NULL;
        return;
    }
    
    char *buf = (char *)os_malloc(1500);
    if (!buf) {
        scan_pending = false;
        scan_conn = NULL;
        return;
    }
    
    int len = 0;
    buf[len++] = '[';
    
    if (status == OK) {
        struct bss_info *bss = (struct bss_info *)arg;
        bool first = true;
        while (bss && len < 1400) {
            if (!first) buf[len++] = ',';
            first = false;
            
            char ssid_escaped[34];
            json_escape(ssid_escaped, (char*)bss->ssid, 33);
            
            const char *enc = "OPEN";
            if (bss->authmode == AUTH_WEP) enc = "WEP";
            else if (bss->authmode == AUTH_WPA_PSK) enc = "WPA";
            else if (bss->authmode == AUTH_WPA2_PSK) enc = "WPA2";
            else if (bss->authmode == AUTH_WPA_WPA2_PSK) enc = "WPA/WPA2";
            
            len += os_sprintf(buf + len, "{\"ssid\":\"%s\",\"rssi\":%d,\"encryption\":\"%s\"}",
                             ssid_escaped, bss->rssi, enc);
            bss = bss->next.stqe_next;
        }
    }
    buf[len++] = ']';
    buf[len] = '\0';
    
    char hdr[128];
    os_sprintf(hdr, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", len);
    espconn_send(scan_conn, (uint8_t *)hdr, os_strlen(hdr));
    espconn_send(scan_conn, (uint8_t *)buf, len);
    
    os_free(buf);
    scan_pending = false;
    scan_conn = NULL;
}

// GET /api/config
static void ICACHE_FLASH_ATTR api_get_config(struct espconn *pespconn) {
    char *buf = (char *)os_malloc(256);
    if (!buf) return;
    
    char sta_ssid[33] = "", sta_pass[33] = "";
    char ap_ssid[33] = "", ap_pass[33] = "";
    
    struct station_config sta_conf;
    if (wifi_station_get_config(&sta_conf)) {
        os_memcpy(sta_ssid, sta_conf.ssid, 32);
        sta_ssid[32] = '\0';
        os_memcpy(sta_pass, sta_conf.password, 32);
        sta_pass[32] = '\0';
    }
    
    struct softap_config ap_conf;
    if (wifi_softap_get_config(&ap_conf)) {
        os_memcpy(ap_ssid, ap_conf.ssid, 32);
        ap_ssid[32] = '\0';
        // Password is not readable from softap_config, use config struct
        os_memcpy(ap_pass, config.ap_password, 32);
        ap_pass[32] = '\0';
    }
    
    os_sprintf(buf, "{\"sta_ssid\":\"%s\",\"sta_password\":\"%s\",\"ap_ssid\":\"%s\",\"ap_password\":\"%s\"}",
               sta_ssid, sta_pass, ap_ssid, ap_pass);
    
    char hdr[128];
    os_sprintf(hdr, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", os_strlen(buf));
    espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
    espconn_send(pespconn, (uint8_t *)buf, os_strlen(buf));
    os_free(buf);
}

// POST /api/config - parse JSON body
static void ICACHE_FLASH_ATTR api_post_config(struct espconn *pespconn, char *body, unsigned short len) {
    char *p = body;
    char key[32], val[64];
    bool changed = false;
    
    // Simple JSON parser - look for "key":"value" patterns
    while (*p && p < body + len) {
        // Find key
        char *ks = os_strchr(p, '"');
        if (!ks) break;
        ks++;
        char *ke = os_strchr(ks, '"');
        if (!ke) break;
        int klen = ke - ks;
        if (klen >= 32) klen = 31;
        os_memcpy(key, ks, klen);
        key[klen] = '\0';
        
        // Find value
        char *vs = os_strchr(ke + 1, ':');
        if (!vs) break;
        vs++;
        while (*vs == ' ') vs++;
        if (*vs != '"') { p = vs; continue; }
        vs++;
        char *ve = os_strchr(vs, '"');
        if (!ve) break;
        int vlen = ve - vs;
        if (vlen >= 64) vlen = 63;
        os_memcpy(val, vs, vlen);
        val[vlen] = '\0';
        
        // Apply config
        if (os_strcmp(key, "sta_ssid") == 0 && val[0]) {
            wifi_station_set_hostname(val);
            changed = true;
        } else if (os_strcmp(key, "sta_password") == 0 && val[0]) {
            changed = true;
        } else if (os_strcmp(key, "ap_ssid") == 0 && val[0]) {
            os_strncpy(config.ap_ssid, val, 32);
            changed = true;
        } else if (os_strcmp(key, "ap_password") == 0) {
            os_strncpy(config.ap_password, val[0] ? val : "", 32);
            config.ap_open = (val[0] == '\0');
            changed = true;
        }
        
        p = ve + 1;
    }
    
    if (changed) {
        config_save(&config);
    }
    
    char resp[] = "{\"success\":true}";
    char hdr[128];
    os_sprintf(hdr, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", sizeof(resp)-1);
    espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
    espconn_send(pespconn, (uint8_t *)resp, sizeof(resp)-1);
}

// POST /api/kick
static void ICACHE_FLASH_ATTR api_post_kick(struct espconn *pespconn, char *body, unsigned short len) {
    // Parse MAC from {"mac":"XX:XX:XX:XX:XX:XX"}
    char *ms = os_strstr(body, "\"mac\"");
    if (!ms) {
        char err[] = "{\"error\":\"No MAC\"}";
        char hdr[128];
        os_sprintf(hdr, "HTTP/1.0 400 Bad Request\r\nContent-Type: application/json\r\n\r\n");
        espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
        espconn_send(pespconn, (uint8_t *)err, sizeof(err)-1);
        return;
    }
    
    ms = os_strchr(ms, ':');
    if (!ms) return;
    ms++;
    char mac_str[18] = {0};
    char *me = os_strchr(ms, '"');
    if (me && (me - ms) < 18) {
        os_memcpy(mac_str, ms, me - ms);
    }
    
    // Convert to bytes
    uint8_t mac[6];
    int matched = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                         &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    
    if (matched == 6) {
        // Deauthenticate client - use sdk function
        wifi_softap_deauth(mac);
        char resp[] = "{\"success\":true}";
        char hdr[128];
        os_sprintf(hdr, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", sizeof(resp)-1);
        espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
        espconn_send(pespconn, (uint8_t *)resp, sizeof(resp)-1);
    } else {
        char err[] = "{\"error\":\"Invalid MAC\"}";
        char hdr[128];
        os_sprintf(hdr, "HTTP/1.0 400 Bad Request\r\nContent-Type: application/json\r\n\r\n");
        espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
        espconn_send(pespconn, (uint8_t *)err, sizeof(err)-1);
    }
}

// POST /api/command
static void ICACHE_FLASH_ATTR api_post_command(struct espconn *pespconn, char *body, unsigned short len) {
    char *cs = os_strstr(body, "\"cmd\"");
    if (!cs) {
        char err[] = "{\"error\":\"No command\"}";
        char hdr[128];
        os_sprintf(hdr, "HTTP/1.0 400 Bad Request\r\nContent-Type: application/json\r\n\r\n");
        espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
        espconn_send(pespconn, (uint8_t *)err, sizeof(err)-1);
        return;
    }
    
    cs = os_strchr(cs, ':');
    if (!cs) return;
    cs++;
    while (*cs == ' ') cs++;
    if (*cs != '"') return;
    cs++;
    
    if (os_strncmp(cs, "reset", 5) == 0) {
        char resp[] = "{\"success\":true}";
        char hdr[128];
        os_sprintf(hdr, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", sizeof(resp)-1);
        espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
        espconn_send(pespconn, (uint8_t *)resp, sizeof(resp)-1);
        // Delay restart slightly to allow response to be sent
        system_restart();
    } else {
        char err[] = "{\"error\":\"Unknown command\"}";
        char hdr[128];
        os_sprintf(hdr, "HTTP/1.0 400 Bad Request\r\nContent-Type: application/json\r\n\r\n");
        espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
        espconn_send(pespconn, (uint8_t *)err, sizeof(err)-1);
    }
}

// Main API request handler
bool ICACHE_FLASH_ATTR api_handle_request(struct espconn *pespconn, char *data, unsigned short length) {
    // Check if this is an API request
    if (os_strncmp(data, "GET /api/", 9) != 0 && os_strncmp(data, "POST /api/", 10) != 0) {
        return false;
    }
    
    // Extract path
    char *path_start = data + 4; // Skip "GET " or "POST"
    while (*path_start == ' ') path_start++;
    
    char *path_end = os_strchr(path_start, ' ');
    if (!path_end) return false;
    
    int path_len = path_end - path_start;
    char path[32];
    if (path_len >= 32) path_len = 31;
    os_memcpy(path, path_start, path_len);
    path[path_len] = '\0';
    
    // Route requests
    if (os_strcmp(path, "/api/status") == 0) {
        api_get_status(pespconn);
        return true;
    }
    
    if (os_strcmp(path, "/api/scan") == 0) {
        api_get_scan(pespconn);
        return true;
    }
    
    if (os_strcmp(path, "/api/config") == 0) {
        if (os_strncmp(data, "GET", 3) == 0) {
            api_get_config(pespconn);
        } else {
            // Find body after headers
            char *body = os_strstr(data, "\r\n\r\n");
            if (body) {
                body += 4;
                api_post_config(pespconn, body, length - (body - data));
            }
        }
        return true;
    }
    
    if (os_strcmp(path, "/api/kick") == 0) {
        char *body = os_strstr(data, "\r\n\r\n");
        if (body) {
            body += 4;
            api_post_kick(pespconn, body, length - (body - data));
        }
        return true;
    }
    
    if (os_strcmp(path, "/api/command") == 0) {
        char *body = os_strstr(data, "\r\n\r\n");
        if (body) {
            body += 4;
            api_post_command(pespconn, body, length - (body - data));
        }
        return true;
    }
    
    // Unknown API endpoint
    char err[] = "{\"error\":\"Not found\"}";
    char hdr[128];
    os_sprintf(hdr, "HTTP/1.0 404 Not Found\r\nContent-Type: application/json\r\n\r\n");
    espconn_send(pespconn, (uint8_t *)hdr, os_strlen(hdr));
    espconn_send(pespconn, (uint8_t *)err, sizeof(err)-1);
    return true;
}

void ICACHE_FLASH_ATTR api_init(void) {
    // Nothing special to initialize
}
