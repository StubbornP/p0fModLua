
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>

#include "library.h"

#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "process.h"
#include "readfp.h"
#include "tcp.h"
#include "fp_http.h"
#include "p0f.h"

#ifndef PF_INET6
#  define PF_INET6          10
#endif /* !PF_INET6 */

#ifndef O_NOFOLLOW
#  define O_NOFOLLOW 0
#endif /* !O_NOFOLLOW */

#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif /* !O_LARGEFILE */

u32
        max_conn        = MAX_CONN,           /* Connection entry count limit       */
        max_hosts       = MAX_HOSTS,          /* Host cache entry count limit       */
        conn_max_age    = CONN_MAX_AGE,       /* Maximum age of a connection entry  */
        host_idle_limit = HOST_IDLE_LIMIT;    /* Host cache idle timeout            */

u32 hash_seed;                          /* Hash seed                          */

s32 link_type;
u8 * read_file = NULL;

lua_State *current_Machine = NULL;

char cli_addr_buffer[ BUFSIZ ];
char srv_addr_buffer[ BUFSIZ ];


int lua_table_set_integer( lua_State *L, const char *key, lua_Integer value){

    lua_pushstring( L, key);
    lua_pushinteger( L, value);
    lua_settable( L, -3);

    return 0;
}

int lua_table_set_string( lua_State *L, const char *key, const char *value){

    lua_pushstring( L, key);
    lua_pushstring( L, value);
    lua_settable( L, -3);

    return 0;
}

void start_observation(char* keyword, u8 field_cnt, u8 to_srv,
                       struct packet_flow* f) {

        if( NULL != current_Machine){

            unsigned char * client_addr = addr_to_str(f->client->addr, f->client->ip_ver);

            strcpy( cli_addr_buffer, ( char * )client_addr);

            unsigned short  cli_port = f->cli_port;
            unsigned char * server_addr = addr_to_str(f->server->addr, f->client->ip_ver);

            strcpy( srv_addr_buffer, ( char * )server_addr);

            unsigned short  server_port = f->srv_port;

            lua_table_set_string( current_Machine, "clientAddress", (const char * )cli_addr_buffer);
            lua_table_set_integer( current_Machine, "clientPort", ( lua_Integer )cli_port );

            lua_table_set_string( current_Machine, "serverAddress", (const char * )srv_addr_buffer);
            lua_table_set_integer( current_Machine, "serverPort", ( lua_Integer )server_port );

            lua_table_set_integer( current_Machine, "toServer", ( lua_Integer )to_srv );

            lua_table_set_string( current_Machine, "modType", (const char * ) keyword);

        }

//        SAYF(".-[ %s/%u -> ", addr_to_str(f->client->addr, f->client->ip_ver),
//             f->cli_port);
//        SAYF("%s/%u (%s) ]-\n|\n", addr_to_str(f->server->addr, f->client->ip_ver),
//             f->srv_port, keyword);
//
//        SAYF("| %-8s = %s/%u\n", to_srv ? "client" : "server",
//             addr_to_str(to_srv ? f->client->addr :
//                         f->server->addr, f->client->ip_ver),
//             to_srv ? f->cli_port : f->srv_port);

}

void add_observation_field(char* key, u8* value) {

    if( NULL != current_Machine){

        lua_table_set_string( current_Machine, key , ( const char * )value);
    }
//    SAYF("| %-8s = %s\n", key, value ? value : (u8*)"???");
}

static void get_hash_seed(void) {

    s32 f = open("/dev/urandom", O_RDONLY);

    if (f < 0) PFATAL("Cannot open /dev/urandom for reading.");

#ifndef DEBUG_BUILD

    /* In debug versions, use a constant seed. */

    if (read(f, &hash_seed, sizeof(hash_seed)) != sizeof(hash_seed))
        FATAL("Cannot read data from /dev/urandom.");

#endif /* !DEBUG_BUILD */

    close(f);

}

int init( lua_State *L){

    const char *config = luaL_checkstring( L, -2 );

    lua_Integer link = luaL_checkinteger( L, -1 );

    link_type = ( s32 )link;

    get_hash_seed();
    http_init();
    read_config( (u8 *)config );

    return 0;
}
int process( lua_State *L){

    lua_Integer  packet = luaL_checkinteger( L, -5 );
    lua_Integer  len = luaL_checkinteger( L, -4 );
    lua_Integer  caplen = luaL_checkinteger( L, -3 );
    lua_Integer  ts_sec = luaL_checkinteger( L, -2 );
    lua_Integer  ts_usec = luaL_checkinteger( L, -1 );

    current_Machine = L;

    lua_newtable( L );

    struct pcap_pkthdr pkthdr;

    pkthdr.len = (unsigned int)len;
    pkthdr.caplen = (unsigned int)caplen;
    pkthdr.ts.tv_sec = ts_sec;
    pkthdr.ts.tv_usec = ts_usec;

    parse_packet( 0, &pkthdr, ( u8* )packet);

    current_Machine = NULL;

    return 1;
}

luaL_Reg functionTable[] = {

        { "modP0FInit", init},
        { "modP0FProcess", process},
};

int luaopen_modP0F( lua_State *L ){

    lua_newtable( L );
    luaL_setfuncs( L, functionTable, 0);

    return 1;
}
