/* 
 * mod_mbedtls - mbedTLS support for lighttpd
 *
 * Currently supported configuration directives:
 *
 *  mbedtls.engine  - boolean, turn mbedTLS on or off in the current configuration context
 *  mbedtls.pemfile - path to a file containing the server's certificate and private key in PEM format
 *
 * Features still to be implemented:
 *   - client verification
 *   - delivering a certificate authorithy chain to the client
 *   - cipher suite selection
 *   - keep-alive, read ahead
 *   - TLS protocol version control/restriction
 *   - renegotiation denial
 *   - environment population with REMOTE_USER and etc.
 *   - connection caching
 *   - SNI
 *   - putting mtls structs on the heap so config context clones are smaller
 *
 * Conventions:
 *   - all configuration commands and outward-facing interfaces prefixed with "mbedtls"
 *   - all internal APIs prefixed with "mtls"
 *   - translation unit local static function names end with "_"
 *   
 * Untested:
 *   - CMake build
 *   - gcc compile
 *   - enabling both mod_openssl and mod_mbedtls together, which should be possible
 *   
 *
 */
#include "first.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "base.h"
#include "log.h"
#include "plugin.h"

#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER >= 0x02040000
#include <mbedtls/net_sockets.h>
#else
#include <mbedtls/net.h>
#endif
#include <mbedtls/ssl.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>

#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? a : b)
#endif

typedef struct {
    unsigned short mtls_log_noise;      /* hook the mtls debug message callback */
    unsigned short mtls_log_level;      /* volume level for above */
    unsigned short mtls_enabled;        /* activate the mtls engine in this context */
    buffer*  mtls_pemfile_path;         /* path to a file containing the server's cert and private key */
    mbedtls_x509_crt server_cert;       /* parsed public key structure */
    mbedtls_pk_context pk_context;      /* parsed private key structure */
    mbedtls_ctr_drbg_context ctr_drbg;  /* NIST counter-mode deterministic random byte generator */
    mbedtls_entropy_context entropy;    /* entropy collection and state management */
    mbedtls_ssl_config* ssl_cfg;        /* context shared between mbedtls_ssl_CONTEXT structures */
} plugin_config;

typedef struct {
    PLUGIN_DATA;                      /* contains idx id */
    plugin_config** config_storage;   /* pointer to array ADT of plugin_config ptrs, 1 global, 1 for each conditional ctx */
} plugin_data;

/* this anchors the array of plugin data for each config context so they can be
.. found by id when ho handler_ctx is available */
static plugin_data *plugin_data_singleton;  

typedef struct {
    connection* con;              /* lighttpd connection object */
    server* srv;                  /* lighttod server object */
    mbedtls_ssl_context ssl;      /* mbedtls request/connection context */    
    plugin_config conf;           /* config settings for this connection ctx */
} handler_ctx;

/*------------------------------------------------------------------------------
Debugging / Development
------------------------------------------------------------------------------*/
#define MTLS_DEBUG 0
#if MTLS_DEBUG
# include "stdarg.h"
#define DBP(...) dbp_( __VA_ARGS__ )
static void dbp_( const char* const pszFormat, ... )
{
    va_list arg_list;
    va_start( arg_list, pszFormat );
    vfprintf( stderr, pszFormat, arg_list );
    va_end( arg_list );
}
#else
# define DBP(...)
#endif // MTLS_DEBUG
/*------------------------------------------------------------------------------
Utility Helpers
------------------------------------------------------------------------------*/
static handler_ctx* handler_ctx_init_(void)
{
    /* make a connection handler context */
    handler_ctx* const hctx = calloc(1, sizeof(*hctx));
    force_assert(hctx);
    return hctx;
}
/*------------------------------------------------------------------------------*/
static void
handler_ctx_free_( handler_ctx* const hctx )
{
    /* free a connection handler context */
    if ( NULL != hctx )
    {
        mbedtls_ssl_free( &hctx->ssl );
        free( hctx );
    }
}
/*------------------------------------------------------------------------------*/
static void elog_( server* srv,
                   const char* const pszFile, const int nLine,
                   const int rc, const char* const pszMsg )
{
    /* error logging convenience function that decodes mbedtls result codes */

    char szBuf[256];

#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror( rc, szBuf, sizeof(szBuf) );
#else
    strcpy( szBuf, "No error string available. "
                   "Compile mbedtls with MBEDTLS_ERROR_C to enable." );
#endif    

    if ( NULL == pszMsg )
    {
        DBP( "mod_mbedtls.c: %s %d %s (-%X)\n", pszFile, nLine, szBuf, rc ); 
        log_error_write( srv, pszFile, nLine, "ssSXS",
                         "MTLS:", szBuf, "(-", -rc, ")" );
    }
    else
    {
        DBP( "mod_mbedtls.c %s %d %s : %s (-%X)\n", \
              pszFile, nLine, pszMsg, szBuf, rc );
        log_error_write( srv, pszFile, nLine, "ssssSXS",
                         "MTLS:", pszMsg, ":", szBuf, "(-", -rc, ")" );
    }
}
/*------------------------------------------------------------------------------*/
static void
mtls_debug_callback_( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    DBP("*** dbg cb: %d %s:%d %s\n", level, file, line, str ); 

    handler_ctx* const hctx = (handler_ctx* const) ctx;

    if ( level >= hctx->conf.mtls_log_level )
    {
        log_error_write( hctx->srv, file, line, "sS",
                         "MTLS:", str );
    }
}
/*------------------------------------------------------------------------------*/
static int
load_next_chunk_(server* const srv, chunkqueue* const cq, const off_t max_bytes,
                 char** const data, size_t* const data_len)
{
    /* read cleartext from memory or file into chunk queue chunk for
       ..encryption and transmission via mbedTLS */
    int rc;

    chunk* const c = cq->first;

    force_assert( NULL != c );

    if ( c->type == MEM_CHUNK )
    {
        /* ofs sensible? And I guess they run it 1 past end when done */
        force_assert(c->offset >= 0
                     && c->offset <= (off_t)buffer_string_length(c->mem));

        *data = c->mem->ptr + c->offset;
        *data_len = MIN( buffer_string_length(c->mem) - c->offset, (size_t) max_bytes);
        rc = 0;
    }
    else if ( c->type == FILE_CHUNK )
    {
        if ( chunkqueue_open_file_chunk(srv, cq) != 0 )  /* open file named in file chunk */
            rc = -1;
        else
        {
            off_t offset;
            ssize_t bytes_to_move;

            force_assert(c->offset >= 0 && c->offset <= c->file.length);
            offset = c->file.start + c->offset;
            bytes_to_move = MIN( c->file.length - c->offset, max_bytes );

            const size_t buffer_have = buffer_string_space( srv->tmp_buf );
            if ( (off_t) buffer_have < max_bytes )
                buffer_string_prepare_append( srv->tmp_buf, bytes_to_move );
            if ( srv->tmp_buf->ptr == NULL ) return -1;
            
            DBP( "Trying to read %d bytes into mem_ptr %p\n", \
                  (int) bytes_to_move, (void*) srv->tmp_buf->ptr );

            if (-1 == lseek(c->file.fd, offset, SEEK_SET))
            {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "lseek: ", strerror(errno));
                rc = -1;
            }
            else if (-1 == ( bytes_to_move = read( c->file.fd, srv->tmp_buf->ptr, bytes_to_move)))
            {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "read: ", strerror(errno));
                rc = -1;
            }
            else
            {
                /* not going to commit srv->tmp_buf because no one looks inside it */
                *data     =  srv->tmp_buf->ptr;
                *data_len =  bytes_to_move;
                rc = 0;
            }
        }
    }
    else
    {
        force_assert( 0 && "unknown chunk type" );
        rc = -1;
    }
    return rc;
}
/*------------------------------------------------------------------------------
Send and Receive Callbacks (sockets below mbedTLS and lighttpd/TLS above)
------------------------------------------------------------------------------*/

/* These low-level socket routines that move bytes into and out of the bottom
...of mbedTLS are pretty much cribbed from mbedTLS net module. Think it is
...clearer not to use that stuff and simpler not to have it as a requirement. */

static int socket_would_block_( const int fd )
{
    /* Check if the requested operation would be blocking on a non-blocking
    .. socket and thus 'failed' with a negative return value.
    .. Note: on a blocking socket this function always returns 0!
    */

    if( ( fcntl( fd, F_GETFL ) & O_NONBLOCK ) != O_NONBLOCK )
        return 0;   /* if non-blocking, return no */

    switch( errno )
    {
#if defined EAGAIN
        case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return 1;
    }
    return  0;
}
/*-----------------------------------------------------------------------------*/
static int
mtls_socket_send_( void* ctx, const unsigned char* buf, size_t len )
{
    /* send encrypted bytes from mbedTLS out the low-level socket */

    DBP("Socket tx\n");

    int ret;

    const int fd = *((int*) ctx);

    if( fd < 0 )
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    ret = (int) write( fd, buf, len );

    if( ret < 0 )
    {
        if( socket_would_block_( fd ) != 0 )
            return MBEDTLS_ERR_SSL_WANT_WRITE;

        if( errno == EPIPE || errno == ECONNRESET )
            return MBEDTLS_ERR_NET_CONN_RESET;

        if( errno == EINTR )
            return MBEDTLS_ERR_SSL_WANT_WRITE;

        DBP( "Socket write error %d\n", ret );

        return( MBEDTLS_ERR_NET_SEND_FAILED );
    }

    DBP( "Wrote %d bytes to socket\n", ret ); 

    return ret;
}
/*-----------------------------------------------------------------------------*/
static int
mtls_socket_receive_( void* ctx, unsigned char* buf, size_t len )
{
    /* Push bytes into mbedTLS from the low-level socket, non-blocking */
    DBP( "Socket rx\n" );

    int ret;

    const int fd = *((int*) ctx);

    if( fd < 0 )
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    ret = (int) read( fd, buf, len );

    if( ret < 0 )
    {
        if( socket_would_block_( fd ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_READ );

        if( errno == EPIPE || errno == ECONNRESET )
            return MBEDTLS_ERR_NET_CONN_RESET;

        if( errno == EINTR )
            return MBEDTLS_ERR_SSL_WANT_READ;

        DBP( "read error %d\n", ret );

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    DBP( "Red %d bytes\n", ret );

    return( ret );
}
/*-----------------------------------------------------------------------------*/
static int
mtls_socket_receive_timeout_( void* ctx, unsigned char* buf,
                              size_t len, uint32_t timeout )
{
    /* push bytes into mbedTLS from the low-level socket, blocking w/timeout */

    DBP( "rx timeout\n" );

    int ret;
    struct timeval tv;
    fd_set read_fds;

    const int fd = *((int*) ctx);

    if( fd < 0 )
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    FD_ZERO( &read_fds );
    FD_SET( fd, &read_fds );

    tv.tv_sec  = timeout / 1000;
    tv.tv_usec = ( timeout % 1000 ) * 1000;

    ret = select( fd + 1, &read_fds, NULL, NULL, timeout == 0 ? NULL : &tv );

    /* Zero fds ready means we timed out */
    if( ret == 0 )
        return MBEDTLS_ERR_SSL_TIMEOUT;

    if( ret < 0 )
    {
        if( errno == EINTR )
            return MBEDTLS_ERR_SSL_WANT_READ;

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    /* This call will not block */
    return( mtls_socket_receive_( ctx, buf, len ) );
}
/*-----------------------------------------------------------------------------*/
static int
connection_write_cq_into_mtls_(server *srv, connection *con,
                               chunkqueue *cq, off_t max_bytes)
{
    /* Push the lighty core's chunk queue data into mbedtls for xmission
     ..over the network */

    DBP( "write from chunk queue max_bytes=%lu\n", \
          (unsigned long) max_bytes ); 

    handler_ctx* hctx = con->plugin_ctx[plugin_data_singleton->id];
    mbedtls_ssl_context* const ssl = &hctx->ssl;

    /* Internet Explorer and wget like to close the connection without issuing
       .. a shutdown request if keep-alive is disabled */

// @todo    if (con->keep_alive == 0) {
//        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
//    }

    chunkqueue_remove_finished_chunks(cq);  /* in chunk.c */

    /* prepare file read buffer */ 
    buffer_string_set_length( srv->tmp_buf,0 );  

    while (max_bytes > 0 && NULL != cq->first)
    {
        char* data;
        size_t data_len;
        int rc;

        if (0 != load_next_chunk_(srv,cq,max_bytes,&data,&data_len)) return -1;

#if 0
        fprintf( stderr, "\n" );
        fwrite( data, data_len, 1, stderr );  // DEBUG 15May17ww
        fprintf( stderr, "\n" );
#endif

        while( (rc = mbedtls_ssl_write( ssl, (unsigned char*) data, data_len )) <= 0 )
        {
            if( rc == MBEDTLS_ERR_NET_CONN_RESET )
            {
                elog_( srv, __FILE__, __LINE__, rc, "peer closed connection" );
                return -1;
            }
            else if( rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                elog_( srv, __FILE__, __LINE__, rc, NULL );
                return -1;
            }
            else if ( MBEDTLS_ERR_SSL_WANT_READ == rc )
            {
                con->is_readable = -1;
            }
            else /* is MBEDTLS_ERR_SSL_WANT_WRITE  */
            {
                con->is_writable = -1;
            }
            return 0;   /* try again later */
        }
        chunkqueue_mark_written(cq, rc);
        max_bytes -= rc;

        if ((size_t) rc < data_len) break; /* try again later */
    }

    /* relase any big memory we allocated */
    buffer_reset( srv->tmp_buf );

    return 0;
}
/*-----------------------------------------------------------------------------*/
static int
connection_read_mtls_into_cq_(server *srv, connection *con,
                              chunkqueue *cq, off_t max_bytes)
{
    DBP( "read into chunk queue\n" ); 

    handler_ctx* hctx = con->plugin_ctx[plugin_data_singleton->id];  // pull our ctx
    int rc, len;

    char* mem = NULL;
    size_t mem_len = 0;

    /*(code transform assumption; minimize diff) <--- what does this mean? Want to know when internals change,
     * or is it because he didn't use cq but con->read_queue in here? or what? 26Apr17ww */
    force_assert(cq == con->read_queue);
    UNUSED(max_bytes);

    do
    {
        /* get memory to read into */
        chunkqueue_get_memory(con->read_queue,
                              &mem, &mem_len,                            /* routine output */
                              0,                                         /* min size */
                              mbedtls_ssl_get_bytes_avail(&hctx->ssl));  /* max we can read */
#if 0
        /* overwrite everything with 0 */
        memset(mem, 0, mem_len);
#endif

        len = mbedtls_ssl_read(&hctx->ssl, (unsigned char*) mem, mem_len);

        if (len > 0)
        {
            chunkqueue_use_memory(con->read_queue, len);
            con->bytes_read += len;
        }
        else
        {  /* 0 read or error, nothing in cq used */
            chunkqueue_use_memory(con->read_queue, 0);
            rc = len;  /* in case an error, alias to a better name */
        }

        /* @todo: renegotiation config chk here */

    } while ( len > 0 && mbedtls_ssl_get_bytes_avail(&hctx->ssl) > 0 );
    
    if ( len < 0 )    /* there was an error or other concern */
    {
        switch( rc )
        {
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                con->is_writable = -1;
                /* fallthru */
            case MBEDTLS_ERR_SSL_WANT_READ:
                con->is_readable = 0;
                return 0;      /* and come around again */
            case MBEDTLS_ERR_NET_CONN_RESET:
                mbedtls_ssl_session_reset(&hctx->ssl);   /* client is banging in afresh */
                return -1;   /* don't allow this, hang up */
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                return 0;  /* peer closed gracefully */
            default:
                elog_( srv,__FILE__,__LINE__, rc, "Reading mbedtls" );
                return -1;
        }
    }
    else if ( len == 0 )
    {
        con->is_readable = 0;
        /* the other end closed the connection -> KEEP-ALIVE */
        return -2;
    }
    else
    {
        return 0;
    }
}
/*------------------------------------------------------------------------------
Private Core Interface Helpers
------------------------------------------------------------------------------*/
static int
load_certs_and_setup_mbedtls_from_config_options_(server* const srv,
                                                  void* const p_d)
{
    /* called from set_defualts callback before root privs dropped.
       ..Time to setup mbedtls structures and load certs */

    plugin_data *p = p_d;
    int rc;

    plugin_config* const pDef = p->config_storage[0];  /* get default context */

    mbedtls_ctr_drbg_init( &pDef->ctr_drbg ); /* initi empty NSIT random number generator */
    mbedtls_entropy_init( &pDef->entropy );   /* init empty entropy collection struct
                                               .. could add sources here too */
    
    /* init RNG */
    rc = mbedtls_ctr_drbg_seed( &pDef->ctr_drbg,      /* random number generator */
                                mbedtls_entropy_func, /* default entropy collector */
                                &pDef->entropy,       /* entropy context */
                                NULL, 0 );            /* no personalization data */
    if( rc != 0 )
    {
        elog_( srv, __FILE__,__LINE__, rc, "Init of random number generator failed" );
        return -1;
    }
    
    mbedtls_pk_init( &pDef->pk_context );  /* init private key context */
    
    /* Allocate a pointer to an ssl_cfg to be shared across connections */
    pDef->ssl_cfg = (mbedtls_ssl_config*) calloc( 1, sizeof(mbedtls_ssl_config) );
    force_assert( pDef->ssl_cfg );
    
    DBP( "outer ssl_cfg at %p\n", (void*) pDef->ssl_cfg ); 

    mbedtls_ssl_config_init( pDef->ssl_cfg );   /* initialize empty config structure */

    rc = mbedtls_ssl_config_defaults( pDef->ssl_cfg,   /* set reasonable defaults, for now */
                                      MBEDTLS_SSL_IS_SERVER,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT  ); 
    if( rc != 0)
    {
        elog_( srv, __FILE__,__LINE__, rc, "Init of ssl config context defaults failed" );
        free( pDef->ssl_cfg ); pDef->ssl_cfg = NULL;
        return -1;
    }

    /* set the RNG in the ssl config context, using the default random func */
    mbedtls_ssl_conf_rng( pDef->ssl_cfg, mbedtls_ctr_drbg_random, &pDef->ctr_drbg );

    /* load SSL certificates */
    for ( size_t ii = 0; ii < srv->config_context->used; ++ii )
    {
        plugin_config* const s = p->config_storage[ ii ];  /* pull settings for this config context */

        if ( s->mtls_enabled )
        {
            if ( buffer_string_is_empty(s->mtls_pemfile_path) ) /* this is a clone */
            {
                /* inherit ssl settings from global scope
                 ..(if only mtls.engine = "enable" and no other mtls.* settings)*/
                if (0 != ii && pDef->mtls_enabled)          /* if this not global, but enabled there... */
                {
                    s->ssl_cfg = pDef->ssl_cfg;             /* take the default mtls ssl config ptr  */
                    continue;
                }
                /* PEM file not set, but did not bring one in either */
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "MTLS: mtls.pemfile must be set");
                return -1;
            }
        }

        DBP( "pemfile: '%s'\n", s->mtls_pemfile_path->ptr );

        if ( buffer_string_is_empty(s->mtls_pemfile_path) ) /* this is a clone, take default */
        {
            DBP( "clone found at index %d Looping.\n", (int) ii );
            continue; 
        }
        
        /* else, this is original */

        DBP( "Original config context load certs at index %d\n", (int) ii );

        /* at this point, we at least have enable + a pemfile */

        /* read public server cert into config context */
        rc = mbedtls_x509_crt_parse_file( &s->server_cert, s->mtls_pemfile_path->ptr );
        if ( 0 != rc )
        {
            elog_(srv,__FILE__,__LINE__,rc,"PEM file cert read failed");
            return -1;
        }
        
        /* read private key from same file */
        rc = mbedtls_pk_parse_keyfile( &s->pk_context, s->mtls_pemfile_path->ptr, NULL ); 
        if ( 0 != rc )
        {
            elog_(srv,__FILE__,__LINE__,rc,"PEM file private key read failed");
            return -1;
        }
//        mbedtls_ssl_conf_ca_chain( pDef->ssl_cfg, s->server_cert.next, NULL );

        rc = mbedtls_ssl_conf_own_cert( pDef->ssl_cfg, &s->server_cert, &s->pk_context );
        if ( 0 != rc )
        {
            elog_(srv,__FILE__,__LINE__,rc,"PEM cert and private key did not verify" );
            return -1;
        }

        DBP( "Certs loaded into non-clone index %d Addr of server cert is %p\n",
                 (int) ii, (void*) &s->server_cert ); 
    }
    
    return 0;
}
/*----------------------------------------------------------------------------*/
#define PATCH(x) \
    hctx->conf.x = s->x;  /* connection context config <--- config file/server context */
static int
mod_mtls_patch_connection_(server *const srv, connection *const con, handler_ctx *const hctx)
{
    /* Move certain outer settings onto the connection context, overidding defaults 
       ...First the global connection context */

    plugin_config* s = plugin_data_singleton->config_storage[0];

    PATCH(mtls_log_noise);  /* global setting is inherited */
    PATCH(mtls_log_level);  /* global setting is inherited */
    PATCH(ssl_cfg);         /* global pointer is inherited */

    /*PATCH(mtls_enabled);*//*(not patched - must be turned on in this config context)*/
    /*PATCH(mtls_pemfile_path);*//*(not patched) - we use as a clone flag */

    /* Now, patch each conditional connection config context...
    ...from the big list in core. skip the first, the global context */
    for (size_t ii = 1; ii < srv->config_context->used; ++ii)
    {
        data_config* const dc = (data_config * const)srv->config_context->data[ii];  /* get conditional data config */

        /* Does data config match this conditional context? Ask config core... */
        if ( !config_check_cond(srv, con, dc) ) continue;   /* ..no */

        s = plugin_data_singleton->config_storage[ii];  /* get storage for this conditional config context */

        /* merge each outer KV that is overidden into this inner config */
        for (size_t jj = 0; jj < dc->value->used; ++jj)
        {
            data_unset * const du = dc->value->data[jj];

            if ( buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-mbedtls-noise")) )
            {
                PATCH(mtls_log_noise);
            }
            else if ( buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-mbedtls-level") ))
            {
                PATCH(mtls_log_level);
            }
        }
    }
    return 0;
}
#undef PATCH
/*------------------------------------------------------------------------------
MODULE ENTRY POINTS
------------------------------------------------------------------------------*/
INIT_FUNC(mod_mbedtls_init)
{
    /* first call */
    plugin_data_singleton = (plugin_data *)calloc(1, sizeof(plugin_data));
    force_assert(plugin_data_singleton);
    return plugin_data_singleton;
}
/*----------------------------------------------------------------------------*/
SETDEFAULTS_FUNC(mod_mbedtls_set_defaults)
{
    DBP( "mod_mbedtls_set_defaults()\n" );

    /* called to load our global default config values. Running as root here,
     ..so this is also the time when the private key is read (and all the certs)
    */
    plugin_data *p = p_d;
    config_values_t cv[] = {
        /*     key                 dest           type                scope              */
        { "debug.log-mbedtls-noise",   NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
        { "debug.log-mbedtls-level",   NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 0 */
        { "mbedtls.engine",            NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
        { "mbedtls.pemfile",           NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 2 */
        { NULL,                        NULL, T_CONFIG_UNSET,   T_CONFIG_SCOPE_UNSET      }
    };

    if (!p) return HANDLER_ERROR;

    p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));
    force_assert(p->config_storage);

    /* allocate storage for all contexts and pass the addresses of same into core so it
       ..can wire us into its global storage list/tree thing */

    for (size_t ii = 0; ii < srv->config_context->used; ++ii)
    {
        data_config const* config = (data_config const*)srv->config_context->data[ii]; /* data_config in array.h */

        /* allocate and init plugin_config for each context */
        plugin_config* const s = calloc(1, sizeof(plugin_config));
        force_assert(s);

        s->mtls_pemfile_path  = buffer_init();

        /* store it back for future use */
        p->config_storage[ii] = s;

        /* setup config variable addresses on stack */
        cv[0].destination = &s->mtls_log_noise;
        cv[1].destination = &s->mtls_log_level;
        cv[2].destination = &s->mtls_enabled;
        cv[3].destination = s->mtls_pemfile_path;

        /* insert config array into glonal config_data space, first two items are debug.xxx which are server scope */
        if ( 0 != config_insert_values_global( srv, config->value, cv,
                                              (ii < 2)
                                              ? T_CONFIG_SCOPE_SERVER
                                              : T_CONFIG_SCOPE_CONNECTION )
            )
        {
            return HANDLER_ERROR;
        }
        
        if ( 0 != ii && s->mtls_enabled && buffer_string_is_empty(s->mtls_pemfile_path) )  /* clone-ing */
        {
            /* inherit mbed settings from global scope (in load_certs_and_setup_mbed_from_config_options_),
             .. *if* only mbedtls.engine = "enable" (above) and no other mbedtls.* settings)*/
            for (size_t jj = 0; jj < config->value->used; ++jj)
            {
                /* cruise the global tree of opts */
                buffer *k = config->value->data[jj]->key;
                if ( 0 == strncmp(k->ptr, "mbedtls.", sizeof("mbedtls.")-1)  /* one of ours */
                     &&
                     ! buffer_is_equal_string(k, CONST_STR_LEN("mbedtls.engine")) /* something otther than engine */
                   )
                {
                    log_error_write(srv, __FILE__, __LINE__, "sb",
                                    "mbedtls.pemfile has to be set in the same scope "
                                    "as other mbedtls.* directives, unless ONLY "
                                    "mbedtls.engine is set, to inherit mbedtls.* from "
                                    "global scope. Found extra setting: ", k);
                    return HANDLER_ERROR;
                }
            }
        }
    }

    if ( 0 != load_certs_and_setup_mbedtls_from_config_options_( srv, p ) )
        return HANDLER_ERROR;

    return HANDLER_GO_ON;
}
/*----------------------------------------------------------------------------*/
CONNECTION_FUNC(mod_mbedtls_handle_con_accept)  /* srv, con, p_d */
{
    /* A new connection has arrived via accept().  Handle if it is TLS */

    DBP("mod_mbedtls_handle_con_accept()\n"); 

    plugin_data *p = p_d;
    handler_ctx *hctx;
    server_socket *srv_sock = con->srv_socket;
    int rc;

    if ( !srv_sock->is_ssl ) return HANDLER_GO_ON;    /* not TLS, early out */

    hctx = handler_ctx_init_();                     /* make a new connection context */
    hctx->con = con;                                /* store the connection object ptr in it */
    hctx->srv = srv;                                /* and the server obj ptr */

    con->plugin_ctx[p->id] = hctx;                  /* store our connection-specific context in the connection */
    mod_mtls_patch_connection_(srv, con, hctx);     /* patch connection-specific overrides into the context */

    if ( hctx->conf.mtls_log_noise )
    {
        DBP( "Debug noise on\n" ); 
        mbedtls_ssl_conf_dbg( hctx->conf.ssl_cfg, mtls_debug_callback_, hctx );
    }
    else
    {
        DBP( "Debug noise off\n" ); 
    }

    mbedtls_ssl_init( &hctx->ssl );    /* initialize empty ssl connection instance */

    DBP( "Binding ssl_cfg %p to new connection\n", (void*) hctx->conf.ssl_cfg ); 

    rc = mbedtls_ssl_setup( &hctx->ssl, hctx->conf.ssl_cfg  ); /* bind config to connection */
    if( rc != 0)
    {
        elog_(srv,__FILE__,__LINE__, rc, "ssl_setup() failed" );
        return HANDLER_ERROR;
    }

#if 0
    {
        mbedtls_x509_crt* const pCert = hctx->ssl.conf->key_cert->cert;

        DBP( "addr of ca_chain is %p\n", (void*) pCert );

        char szBuf[512];
        mbedtls_x509_crt_info( szBuf, sizeof(szBuf), "--> ", pCert );
        DBP( "%s\n", szBuf );
    }
#endif
    /* connect bottom of mbedTLS to the network socket */
    mbedtls_ssl_set_bio( &hctx->ssl, &con->fd, mtls_socket_send_, mtls_socket_receive_, mtls_socket_receive_timeout_ );

    /* connect top of mbedTLS to the lighttpd core */
    con->network_read  = connection_read_mtls_into_cq_;
    con->network_write = connection_write_cq_into_mtls_;

    /* properly set protocol method in connection */
    buffer_copy_string_len(con->proto, CONST_STR_LEN("https"));

    while( ( rc = mbedtls_ssl_handshake( &hctx->ssl ) ) != 0 )
    {
        if( rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            if( rc != 0)
            {
                elog_( srv, __FILE__, __LINE__, rc, NULL );
                return HANDLER_ERROR;
            }
        }
    }

    return HANDLER_GO_ON;
}
/*----------------------------------------------------------------------------*/
CONNECTION_FUNC(mod_mbedtls_handle_con_shut_wr)
{
    DBP( "mod_mbedtls_handle_con_shut_wr()\n" );

    /* Done with connection. Shutdown TLS channel. Send close-notify to
     ..peer */ 
    int rc;
    plugin_data* const p = p_d;
    handler_ctx* const hctx = con->plugin_ctx[p->id];
    if (NULL == hctx)
    {
        DBP( "hctx null at p->id %d", (int) p->id );
        return HANDLER_GO_ON;
    }

    while( ( rc = mbedtls_ssl_close_notify( &hctx->ssl ) ) < 0 )
    {
        DBP( "ssl_close_notify() %d\n", rc );

        if( rc != MBEDTLS_ERR_SSL_WANT_READ &&
            rc != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            elog_( srv, __FILE__, __LINE__, rc, "mbedtls_ssl_close_notify()" );
            mbedtls_ssl_session_reset( &hctx->ssl );
        }
    }

    DBP( "close notify sent\n" );

    return HANDLER_GO_ON;
}
/*----------------------------------------------------------------------------*/
CONNECTION_FUNC(mod_mbedtls_handle_con_close)
{
    DBP( "mod_mbedtls_handle_con_close\n" ); 

    /* socket is about to close() Final clean up*/

    plugin_data* const p = p_d;
    handler_ctx* const hctx = con->plugin_ctx[p->id];
    if ( NULL != hctx )
    {
        handler_ctx_free_(hctx);  /* release ssl connection context */
        con->plugin_ctx[p->id] = NULL;
    }
    UNUSED(srv);
    return HANDLER_GO_ON;
}
/*----------------------------------------------------------------------------*/
CONNECTION_FUNC(mod_mbedtls_handle_request_env)
{
    /* deferred environment populate */

    DBP( "mod_mbedtls_handle_request_env" ); 
    plugin_data* const p = p_d;
    handler_ctx* hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    UNUSED(srv);
    return HANDLER_GO_ON;
}
/*----------------------------------------------------------------------------*/
CONNECTION_FUNC(mod_mbedtls_handle_uri_raw)
{
    DBP( "mod_mbedtls_handle_uri_raw()\n" );

    /* A new request has just arrived and the HTTP headers have just been
    parsed. patch the outermost connection from global defaults. The
    environment is empty.

    The environment built now will be available to other modules and CGI.
    So, when client verification is implemented here, and on, this module will
    export REMOTE_USER and will need to be loaded before mod_auth.

    When client verification is implemented here, and on, and REMOTE_USER is
    set from the client cert, this module will have to be loaded
    _after_  mod_extforward, because we will override it.

    BUT, if the mod_mbedtls config is based on the lighttpd.conf "remote IP"
    conditional using the remote IP address SET by mod_extforward, *unless*
    PROXY protocol is enabled (with extforward.ha-PROXY = "enable", then
    the reverse is true, and mod_extforward must be loaded AFTER
    mod_mbedtls. */

    plugin_data* const p = p_d;
    handler_ctx* const hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    mod_mtls_patch_connection_(srv, con, hctx);

    return HANDLER_GO_ON;
}
/*----------------------------------------------------------------------------*/
CONNECTION_FUNC(mod_mbedtls_handle_request_reset)
{
    DBP( "mod_mbedtls_handle_request_reset\n" );

    /* after request all done or after a request reset */
    plugin_data* const p = p_d;
    handler_ctx* const hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    UNUSED(srv);
    return HANDLER_GO_ON;
}
/*----------------------------------------------------------------------------*/
FREE_FUNC(mod_mbedtls_free)  /* *srv, *p_d */
{
    DBP( "mod_mbedtls_free()\n" );

    plugin_data *p = p_d;     
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage)
    {
        for (size_t ii = 0; ii < srv->config_context->used; ++ii)
        {
            plugin_config *s = p->config_storage[ii];

            buffer_free( s->mtls_pemfile_path );
            mbedtls_x509_crt_free( &s->server_cert );
            mbedtls_ctr_drbg_free( &s->ctr_drbg );
            mbedtls_entropy_free( &s->entropy );
        }

        mbedtls_ssl_config_free( p->config_storage[0]->ssl_cfg );
        free( p->config_storage[0]->ssl_cfg );

        for (size_t ii = 0; ii < srv->config_context->used; ++ii) {
            plugin_config *s = p->config_storage[ii];
            if (NULL == s) continue;
            free(s);
        }
        free(p->config_storage);
    }

    free(p);

    return HANDLER_GO_ON;
}
/*----------------------------------------------------------------------------*/
int mod_mbedtls_plugin_init (plugin *p)
{
    /* We have been loaded into memory at start of the workd.
     *   tell the core about our entry points. */

    p->version                   = LIGHTTPD_VERSION_ID;
    p->name                      = buffer_init_string("mbedTLS");
    p->init                      = mod_mbedtls_init;
    p->cleanup                   = mod_mbedtls_free;
    p->set_defaults              = mod_mbedtls_set_defaults;
    p->handle_connection_accept  = mod_mbedtls_handle_con_accept;
    p->handle_connection_shut_wr = mod_mbedtls_handle_con_shut_wr;
    p->handle_connection_close   = mod_mbedtls_handle_con_close;
    p->handle_uri_raw            = mod_mbedtls_handle_uri_raw;
    p->handle_request_env        = mod_mbedtls_handle_request_env;
    p->connection_reset          = mod_mbedtls_handle_request_reset;

    p->data         = NULL;

    return 0;
}



/* end: mod_mbedts.c */

