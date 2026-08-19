#include <stdint.h>
#ifdef _WIN32
#define E __declspec(dllexport)
#else
#define E
#endif
E int aegis_packet_parser_init(void){return 0;}
E int aegis_packet_parser_parse(const uint8_t*d,uint32_t l){(void)d;(void)l;return 0;}
E int aegis_packet_parser_get_version(void){return 1;}
E void aegis_packet_parser_cleanup(void){}
