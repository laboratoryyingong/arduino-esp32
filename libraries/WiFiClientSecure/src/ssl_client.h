/* Provide SSL/TLS functions to ESP32 with Arduino IDE
 * by Evandro Copercini - 2017 - Apache 2.0 License
 */

#ifndef ARD_SSL_H
#define ARD_SSL_H
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

typedef struct sslclient_context {
    int socket;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;

    mbedtls_ctr_drbg_context drbg_ctx;
    mbedtls_entropy_context entropy_ctx;

    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;

    unsigned long socket_timeout;
    unsigned long handshake_timeout;
} sslclient_context;


/* splashme field diagnostics -----------------------------------------------
 * Result of the most recent start_ssl_client() attempt, so the device can show
 * on its own LCD whether a connect died in TCP or inside the TLS handshake -
 * and if the latter, at which step - without anyone attaching a programmer.
 * Written only by start_ssl_client (one task at a time); readers just display.
 */
typedef enum {
    SPLASHME_TLS_NONE = 0,     /* no attempt since boot                       */
    SPLASHME_TLS_OK,           /* handshake completed                         */
    SPLASHME_TLS_TCP_FAILED,   /* never reached TLS - TCP/network problem     */
    SPLASHME_TLS_TIMEOUT,      /* handshake started but ran out of time       */
    SPLASHME_TLS_ERROR         /* handshake rejected (cert/protocol/alloc)    */
} splashme_tls_outcome_t;

typedef struct {
    uint32_t attempts;      /* connect attempts since boot                    */
    uint32_t tcp_ms;        /* time spent establishing TCP (last attempt)     */
    uint32_t handshake_ms;  /* time spent in the TLS handshake (last attempt) */
    uint32_t stall_ms;      /* time sat in the final handshake state          */
    int      last_state;    /* mbedtls_ssl_states reached (-1 = never started)*/
    int      last_error;    /* mbedTLS error code, 0 when none                */
    uint8_t  outcome;       /* splashme_tls_outcome_t                         */
} splashme_tls_diag_t;

extern splashme_tls_diag_t g_splashme_tls_diag;
const char *splashme_tls_state_name(int state);

void ssl_init(sslclient_context *ssl_client);
int start_ssl_client(sslclient_context *ssl_client, const IPAddress& ip, uint32_t port, const char* hostname, int timeout, const char *rootCABuff, bool useRootCABundle, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey, bool insecure, const char **alpn_protos);
void stop_ssl_socket(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key);
int data_to_read(sslclient_context *ssl_client);
int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len);
int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length);
bool verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name);
bool verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name);
bool get_peer_fingerprint(sslclient_context *ssl_client, uint8_t sha256[32]);
#endif
