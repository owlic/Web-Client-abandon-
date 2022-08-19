#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define SUCCESS 0
#define BASE 0
#define ERR_ARGC (BASE - 1)
#define ERR_URL_NAME (BASE - 2)
#define ERR_FOLDER_NAME (BASE - 3)
#define ERR_PROCESS_NUMBER (BASE - 4)
#define ERR_OPEN_FAIL (BASE - 5)
#define ERR_LOAD_FAIL (BASE - 6)
#define ERR_SAVE_FAIL (BASE - 7)
#define ERR_MALLOC_FAIL (BASE - 8)
#define PADDING_SIZE 3
#define MAX_URL_SIZE 256
#define MAX_NAME_SIZE 256
#define FOLDER_NAME_SIZE 128
#define REQUEST_SIZE (1 << 10)      //記得括弧
#define RESPONSE_SIZE (1 << 14)     //16Kb
#define BUF_SIZE (1 << 18)
#define CONTENTS "all_url"
#define DEBUG

typedef struct ssl_info
{
    SSL* ssl;
    SSL_CTX* ctx;
    int server;
    BIO* outbio;
}ssl_info;

void ssl_connect(char*, ssl_info*, char*);
void ssl_disconnect(ssl_info*, char*);
int create_socket(char*, BIO*);
void print_ip(struct hostent*);
void get_host_n_path(char*, char*, int, char*, int);
int crawler(SSL*, char*, char*, char*, char*, int);
void make_request_message(char*, char*, char*);
void make_file_name(char*, char*, char*);
int SSL_read_n_write(SSL*, char*, FILE*);
void general_case(SSL*, char*, FILE*, int, int);
void url_convert(char*, char*);
void sub_quit_signal_handle(int);
void parent_cycle(int);
void child_cycle();
void search_link(char*, char*);


int process_complete = 0;
char folder[FOLDER_NAME_SIZE];
char padding[PADDING_SIZE] = {' ', ' ', ' '};

//gcc -o main main.c -lssl -lcrypto
//"https://www.openfind.com.tw/taiwan/", "web/", "5"


int main(int argc, char* argv[])
{
    if(argc != 4)
        return ERR_ARGC;
    
    if(!argv[1])
        return ERR_URL_NAME;
    
    if(!argv[2])
        return ERR_FOLDER_NAME;
    
    int process_total = atoi(argv[3]);
    if (process_total < 1)
        return ERR_PROCESS_NUMBER;

    strncpy(folder, argv[2], FOLDER_NAME_SIZE);

    mkdir(folder, S_IRWXU | S_IRWXG | S_IRWXO);
    //if (mkdir(argv[2], S_IRWXU | S_IRWXG | S_IRWXO)) return errno;
    char contents_file[MAX_NAME_SIZE];
    sprintf(contents_file, "%s%s%s", folder, CONTENTS, ".txt");
    FILE* fptr = fopen(contents_file, "w+");
    if (!fptr)
        return ERR_OPEN_FAIL;
    printf("URL: %s\n", argv[1]);
    fprintf(fptr, "%s%s\n", padding, argv[1]);

    //fwrite(padding, PADDING_SIZE, 1, fptr);
    //fwrite(argv[1], strlen(argv[1]) + 1, 1, fptr);      //'\0'也要複製
    fclose(fptr);

    pid_t pid;
    int i;

    for(i = 0; i < process_total; i++)
	{
		pid = fork();
		if(pid == 0 || pid == -1)
			break;
	}
 
	if(pid == -1)
		printf("No. %d: fork error\n", i);
	else if(pid == 0)
		child_cycle();
	else
		parent_cycle(process_total);

    return 0;
}

void sub_quit_signal_handle(int sig)
{
	int status;
	int quit_pid = wait(&status);

    if (status)
    {
        printf("sub process %d quit, exit status %d\n", quit_pid, status);
        pid_t pid = fork();
        if(pid == 0)
            child_cycle();     //有辦法傳參數進去? sub_quit_signal_handle 只接受一 int 參數
    }
    else
        process_complete++;
}

void parent_cycle(int process_total)
{
	printf("Parent process %d\n", getpid());
	signal(SIGCHLD, sub_quit_signal_handle);
    while(process_complete < process_total)
        sleep(1);
}

void child_cycle()
{
	printf("create sub process id: %d, parent id: %d\n", getpid(), getppid());

    char contents_file[MAX_NAME_SIZE];
    sprintf(contents_file, "%s%s%s", folder, CONTENTS, ".txt");

    while(1)
    {
        FILE* fptr = fopen(contents_file, "r+");
        if (!fptr)
        {
#ifdef DEBUG
            printf("---------------\nfopen error !\n---------------\n");
#endif
            exit(1);
        }
    
        if (flock(fileno(fptr), LOCK_EX))
        {
#ifdef DEBUG
            printf("---------------\nflock error !\n---------------\n");
#endif
            exit(1);
        }

        struct stat fstat;
        stat(contents_file, &fstat);
        int fsize = fstat.st_size;
        if (fsize <= 0)
        {
#ifdef DEBUG
            printf("---------------\ncontents file empty !\n---------------\n");
#endif
            exit(1);
        }
    
        char* contents_buf = malloc(fsize);
        if (!contents_buf)
#ifdef DEBUG
            printf("---------------\nmalloc fail !\n---------------\n");
#endif
    
        if (fread(contents_buf, fsize, 1, fptr) != 1)
#ifdef DEBUG
            printf("---------------\nfread error !\n---------------\n");
#endif

        char* url_loc = strstr(contents_buf, "   http");
        if (url_loc)
        {
            int seek_loc = url_loc - contents_buf;
#ifdef DEBUG
            sleep(1);
            printf("---------------\nseek_loc: %d\n", seek_loc);
#endif
            fseek(fptr, seek_loc, SEEK_SET);
            fprintf(fptr, "%c", '~');
            flock(fileno(fptr), LOCK_UN);
            printf("---------------\nLOCK_UN OK\n");
            fclose(fptr);

            //將網址取出

            url_loc += PADDING_SIZE;
            char* url_end = strchr(url_loc, '\n');
            printf("---------------\nurl_end: %p\n", url_end);
            int url_size = url_end - url_loc;
            printf("---------------\nurl_size: %d\n", url_size);
            //char url[url_size];
            char url[url_size + 1];

            strncpy(url, url_loc, url_size);
            url[url_size] = 0;
            free(contents_buf);

            //將網址抓下
#ifdef DEBUG
            printf("url[0]: %d\n", url[0]);
            printf("url[url_size - 1]: %d\n", url[url_size - 1]);
            printf("url[url_size]: %d\n", url[url_size]);
            printf("抓取 url: %s\n", url);
#endif
            char host[MAX_URL_SIZE];    //統一 size
            char path[MAX_URL_SIZE];
            get_host_n_path(url, host, MAX_URL_SIZE, path, MAX_URL_SIZE);

            printf("----------\nhost: %s\n", host);
            printf("----------\npath: %s\n", path);

            ssl_info* SI;
            ssl_connect(url, SI, host);

            char url_file[MAX_NAME_SIZE];
            char url_move[MAX_URL_SIZE] = {0};    //遇到網址轉移時
            make_file_name(url_file, host, path);

            int result = crawler(SI->ssl, host, path, url_file, url_move, SI->server);
            while (url_move[0])
            {
                ssl_disconnect(SI, url);
                get_host_n_path(url_move, host, MAX_URL_SIZE, path, MAX_URL_SIZE);
#ifdef DEBUG
                printf("----------\nNEW host: %s\n", host);
                printf("----------\nNEW path: %s\n", path);
#endif
                ssl_connect(url_move, SI, host);
                make_file_name(url_file, host, path);
                result = crawler(SI->ssl, host, path, url_file, url_move, SI->server);
            }

            char* link_buf = malloc(BUF_SIZE);
#ifdef DEBUG
            if (!link_buf)
                printf("---------------\nmalloc fail !\n---------------\n");
#endif            
            search_link(url_file, link_buf);
            //printf("---------------\nurl_file: %s\n---------------\n", url_file);
            //printf("---------------\nlink_buf: %s\n---------------\n", link_buf);

            fptr = fopen(contents_file, "r+");
            if (!fptr)
            {
#ifdef DEBUG
                printf("---------------\nfopen error !\n---------------\n");
#endif
                exit(1);
            }

            if (flock(fileno(fptr), LOCK_EX))
            {
#ifdef DEBUG
                printf("---------------\nflock error !\n---------------\n");
#endif
                exit(1);
            }

            //將狀態改成完成
            fseek(fptr, seek_loc, SEEK_SET);
            fprintf(fptr, "%c", '*');

            if (link_buf[0])     //將網址寫回 contents_file
            {
                fseek(fptr, 0, SEEK_END);
                fwrite(link_buf, strlen(link_buf) + 1, 1, fptr);
            }

            flock(fileno(fptr), LOCK_UN);
            fclose(fptr);

            if (url_move[0])
                ssl_disconnect(SI, url_move);
            else
                ssl_disconnect(SI, url);
        }
        else
        {
            flock(fileno(fptr), LOCK_UN);
            fclose(fptr);

            url_loc = strstr(contents_buf, "~  http");
            free(contents_buf);

            if (url_loc)
                sleep(3);       //等等再說
            else
                exit(0);        //子行程結束
        }
    }
}


/* ---------------------------------------------------------- *
 * First we need to make a standard TCP socket connection.    *
 * create_socket() creates a socket & TCP-connects to server. *
 * ---------------------------------------------------------- */

void ssl_connect(char* url, ssl_info* SI, char* host)
{
    BIO  *certbio = NULL;
    BIO  *outbio = NULL;
    X509 *cert = NULL;
    X509_NAME *certname = NULL;
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    int server = 0;
    int ret, i;

    // char url[MAX_URL_SIZE];
    // char host[MAX_URL_SIZE];    //統一 size，不然 define 好雜
    // char path[MAX_URL_SIZE];
    // strncpy(url, target_url, MAX_URL_SIZE - 1);
    // url[MAX_URL_SIZE - 1] = '\0';
    // get_host_n_path(url, host, MAX_URL_SIZE, path, MAX_URL_SIZE);

    // printf("----------\nhost:%s----------\n", path);

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */

    certbio = BIO_new(BIO_s_file());
    SI->outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */

    if(SSL_library_init() < 0)
        BIO_printf(SI->outbio, "Could not initialize the OpenSSL library !\n");

  /* ---------------------------------------------------------- *
   * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
   * ---------------------------------------------------------- */

    //method = SSLv23_client_method();
  
  /* ---------------------------------------------------------- *
   * SSLv23_client_method is deprecated function                *
   * Set TLS client hello by andric                             *
   * ---------------------------------------------------------- */

    method = TLS_client_method();

  /* ---------------------------------------------------------- *
   * Try to create a new SSL context                            *
   * ---------------------------------------------------------- */

    if ((SI->ctx = SSL_CTX_new(method)) == NULL)
        BIO_printf(SI->outbio, "Unable to create a new SSL context structure.\n");

  /* ---------------------------------------------------------- *
   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
   * ---------------------------------------------------------- */

    SSL_CTX_set_options(SI->ctx, SSL_OP_NO_SSLv2);

  /* ---------------------------------------------------------- *
   * Create new SSL connection state object                     *
   * ---------------------------------------------------------- */

    SI->ssl = SSL_new(SI->ctx);

  /* ---------------------------------------------------------- *
   * Make the underlying TCP socket connection                  *
   * ---------------------------------------------------------- */

    SI->server = create_socket(url, SI->outbio);
    if(SI->server != 0)
        BIO_printf(SI->outbio, "Successfully made the TCP connection to: %s\n", url);

  /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor            *
   * ---------------------------------------------------------- */

    SSL_set_fd(SI->ssl, SI->server);

  /* ---------------------------------------------------------- *
   * Set to Support TLS SNI extension by Andric                 *
   * ---------------------------------------------------------- */
    
    SSL_ctrl(SI->ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void*)host);

  /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success             *
   * ---------------------------------------------------------- */

    if ((ret = SSL_connect(SI->ssl)) != 1 )
    {
        int err;
        BIO_printf(SI->outbio, "Error: Could not build a SSL session to: %s\n", url);
    /* ---------------------------------------------------------- *
     * Print SSL-connect error message by andric                  *
     * ---------------------------------------------------------- */
        err = SSL_get_error(SI->ssl, ret);
        if(err == SSL_ERROR_SSL)
        {              
            ERR_load_crypto_strings();
            SSL_load_error_strings(); // just once
            char msg[1024];
            ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
            printf("%s %s %s %s\n", msg, ERR_lib_error_string(0), ERR_func_error_string(0), ERR_reason_error_string(0));
        }
    }
    else
        BIO_printf(SI->outbio, "Successfully enabled SSL/TLS session to: %s\n", url);

  /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure         *
   * ---------------------------------------------------------- */

    // cert = SSL_get_peer_certificate(ssl);
    // if (cert == NULL)
    //     BIO_printf(SI->outbio, "Error: Could not get a certificate from: %s\n", url);
    // else
    //     BIO_printf(SI->outbio, "Retrieved the server's certificate from: %s\n", url);

  /* ---------------------------------------------------------- *
   * extract various certificate information                    *
   * -----------------------------------------------------------*/

    // certname = X509_NAME_new();
    // certname = X509_get_subject_name(cert);

  /* ---------------------------------------------------------- *
   * display the cert subject here                              *
   * -----------------------------------------------------------*/

    // BIO_printf(SI->outbio, "Displaying the certificate subject data:\n");
    // X509_NAME_print_ex(SI->outbio, certname, 0, 0);
    // BIO_printf(SI->outbio, "\n");

  /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/

    // int result = crawler(ssl, host, path, server);
    // char url_file[MAX_NAME_SIZE];
    // make_file_name(url_file, host, path);
    // search_link(url_file);
}


void ssl_disconnect(ssl_info* SI, char* url)
{
    SSL_free(SI->ssl);
    close(SI->server);
    //X509_free(cert);
    SSL_CTX_free(SI->ctx);
    BIO_printf(SI->outbio, "Finished SSL/TLS connection with server: %s\n", url);
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[], BIO* out)
{
    int sockfd;
    char hostname[256] = "";
    char portnum[6] = "443";
    char proto[6] = "";
    char *tmp_ptr = NULL;
    int  port;
    struct hostent *host;
    struct sockaddr_in dest_addr;

  /* ---------------------------------------------------------- *
   * Remove the final / from url_str, if there is one           *
   * ---------------------------------------------------------- */

    if (url_str[strlen(url_str) - 1] == '/')
        url_str[strlen(url_str) - 1] = '\0';

  /* ---------------------------------------------------------- *
   * the first : ends the protocol string, i.e. http            *
   * ---------------------------------------------------------- */
  
    strncpy(proto, url_str, (strchr(url_str, ':') - url_str));          //proto 存 http/https (意義不明，待刪)

  /* ---------------------------------------------------------- *
   * the hostname starts after the "://" part                   *
   * ---------------------------------------------------------- */

    strncpy(hostname, strstr(url_str, "://") + 3, sizeof(hostname));    //前端 :// 以前去掉，存在 hostname

  /* ---------------------------------------------------------- *
   * if the hostname contains a colon :, we got a port number   *
   * ---------------------------------------------------------- */

    if (strchr(hostname, ':'))
    {
        tmp_ptr = strchr(hostname, ':');
        /* the last : starts the port number, if avail, i.e. 8443 */
        strncpy(portnum, tmp_ptr + 1,  sizeof(portnum));
        *tmp_ptr = '\0';
    }

    char* host_end = strchr(hostname, '/');
    if(host_end)
        *host_end = '\0';

    port = atoi(portnum);

    if ((host = gethostbyname(hostname)) == NULL)
    {
        BIO_printf(out, "Error: Cannot resolve hostname %s.\n",  hostname);
        abort();
    }

  /* ---------------------------------------------------------- *
   * Print hostname iP address by Andric                        *
   * ---------------------------------------------------------- */

    //print_ip(host);
  
  /* ---------------------------------------------------------- *
   * create the basic TCP socket                                *
   * ---------------------------------------------------------- */

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

  /* ---------------------------------------------------------- *
   * Zeroing the rest of the struct                             *
   * ---------------------------------------------------------- */

    memset(&(dest_addr.sin_zero), '\0', 8);

    tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  /* ---------------------------------------------------------- *
   * Try to make the host connect here                          *
   * ---------------------------------------------------------- */
  
    if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1)
        BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d.\n", hostname, tmp_ptr, port);

    return sockfd;
}

void print_ip(struct hostent *he)
{
    struct in_addr a;
    char **addr_list;
    char **aliases;
    if (he)
    {
        printf("name: %s\n", he->h_name);
        aliases = he->h_aliases;
        while (*aliases)
            printf("alias: %s\n", *aliases++);

        addr_list = he->h_addr_list;
        while (*addr_list)
        {
            bcopy(*addr_list++, (char *) &a, sizeof(a));
            printf("address: %s\n", inet_ntoa(a));
        }
    }
}


int crawler(SSL* ssl, char* host, char* path, char* url_file, char* url_move, int server)
{
    char request[REQUEST_SIZE];
    char response[RESPONSE_SIZE];

    make_request_message(request, host, path);

    //發送請求
    int ret = SSL_write(ssl, request, strlen(request));     //將緩衝區中的 num 個 byte 寫入指定的 ssl 連接
    if (ret)
        SSL_get_error(ssl, ret);                            //獲取 TLS/SSL I/O 操作的結果
    
    ret = SSL_read(ssl, response, RESPONSE_SIZE);
    if(ret <= 0)
        SSL_get_error(ssl, ret);

    //接收回應
    printf("----------\nResponse: (see %s/%s.txt)\n----------\n", host, path);
    
    char status_code_str[3];
    strncpy(status_code_str, response + 9, 3);
    int status_code = atoi(status_code_str);

    //fwrite(response, ret, 1, fptr);
    //general_case(ssl, response, fptr, server, ret);

    switch (status_code)
    {
        // case 200:
        // case 201:
        // {
        //     FILE* fptr = fopen(url_file, "w+");
        //     if (!fptr)
        //         return ERR_OPEN_FAIL;
        //     fwrite(response, ret, 1, fptr);
        //     general_case(ssl, response, fptr, server, ret);
        //     fclose(fptr);
        //     break;
        // }
        case 301:
        case 302:
        {
            if (remove(url_file))
                printf("------------\nREMOVE FILE FAIL ! - %s\n------------\n", strerror(errno));
            char* new_url_loc = strstr(response, "Location: ");
            new_url_loc += 10;
            char* new_url_end = strchr(new_url_loc, '\n');
            int new_url_len = new_url_end - new_url_loc;
            // printf("------------\nnew_url_len: %d\n", new_url_len);
            strncpy(url_move, new_url_loc, new_url_len);
            url_move[new_url_len - 1] = '\0';      //注意: 在 \n 前面是 \r
            printf("------------\nurl_move: %s\n", url_move);
            // printf("------------\nurl_move[new_url_len - 1]: %d\n", url_move[new_url_len - 1]);
            break;
        }
        default:
        {
            memset(url_move, 0, MAX_URL_SIZE);
            FILE* fptr = fopen(url_file, "w+");
            if (!fptr)
                return ERR_OPEN_FAIL;
            fwrite(response, ret, 1, fptr);
            general_case(ssl, response, fptr, server, ret);
            fclose(fptr);
            break;
        }
        // printf("------------\nNOT SUPPORT !\n------------\n");
    }

    return SUCCESS;
}

void url_convert(char* new_url, char* url)
{
    //檔名太長問題(上限256)

    char* ptr = new_url;

    for(int i = 0; i <= strlen(url); i++)
    {
        switch (url[i])
        {
            case '/':   strcpy(ptr, "∕");
                        ptr += strlen("∕");
                        break;
            case '?':   strcpy(ptr, "？");
                        ptr += strlen("？");
                        break;
            case ':':   strcpy(ptr, "：");
                        ptr += strlen("：");
                        break;
            case '*':   strcpy(ptr, "＊");
                        ptr += strlen("＊");
                        break;
            default:    *ptr++ = url[i];
        }
    }
}

int SSL_read_n_write(SSL* ssl, char* response, FILE* fptr)
{
    int ret = SSL_read(ssl, response, RESPONSE_SIZE);     //嘗試從指定的 ssl 讀取 num 個 byte 到緩衝區 buf 中
    if(ret <= 0)
        SSL_get_error(ssl, ret);
    fwrite(response, ret, 1, fptr);
    return ret;
}

// void make_request_message(char* request, char* host, char* path)
// {
//     char* original_loc = request;
//     strncpy(request, "GET /", 5);
//     request += 5;

//     if (path[0])
//     {
//         strncpy(request, path, strlen(path) + 1);
//         request += strlen(path);
//     }
//     strncpy(request, " HTTP/1.1\r\nHost: ", 17);

//     char* host_loc = strchr(request, ':');
//     strcpy(host_loc + 2, host);
//     strncpy(request + strlen(request), "\r\n\r\n", 5);

//     printf("----------\nRequest:\n----------\n%s\n", original_loc);
// }

void make_request_message(char* request, char* host, char* path)
{
    char* original_loc = request;

    strncpy(request, "GET /", 6);
    if (path[0])
        strncat(request, path, strlen(path) + 1);

    strcat(request, " HTTP/1.1\r\nHost: ");
    strncat(request, host, strlen(host));
    strcat(request, "\r\n\r\n");

    printf("----------\nRequest:\n----------\n%s\n", original_loc);
}

void make_file_name(char* url_file, char* host, char* path)
{
    char host_convert[MAX_NAME_SIZE];
    url_convert(host_convert, host);

    if (path[0])
    {
        char path_convert[MAX_NAME_SIZE];
        url_convert(path_convert, path);
        sprintf(url_file, "%s%s∕%s%s", folder, host_convert, path_convert, ".txt");
    }
    else
        sprintf(url_file, "%s%s%s", folder, host_convert, ".txt");
}

void general_case(SSL* ssl, char* response, FILE* fptr, int server, int ret)
{
    char* transfer_mode = NULL;
    if (transfer_mode = strstr(response, "Transfer-Encoding: chunked"))
    {
        char* ending = NULL;
        while((ending = strstr(response, "0\r\n\r\n")) == NULL)
            SSL_read_n_write(ssl, response, fptr);
    }
    else if ((transfer_mode = strstr(response, "Content-Length: ")) ||
             (transfer_mode = strstr(response, "content-length: ")))
    {
        char* size_loc = transfer_mode + 16;
        int content_length = atoi(size_loc);

        //原寫法
        // int response_times = content_length / RESPONSE_SIZE;
        // if(content_length % RESPONSE_SIZE)
        //     response_times += 1;
        // #ifdef DEBUG
        // printf("---------------\ncontent_length:%d\n", content_length);
        // printf("---------------\nresponse_times:%d\n", response_times);
        // #endif

        ret -= size_loc - response;
        content_length -= ret;
        while (content_length > 0)
            content_length -= SSL_read_n_write(ssl, response, fptr);
    }
    else
    {
        while (1)
        {
            struct timeval timeout;
            timeout.tv_sec = 3;
            timeout.tv_usec = 0;
            setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));     //設置超時時間
            SSL_read_n_write(ssl, response, fptr);
        }
    }
}

void get_host_n_path(char* url, char* host, int host_size, char* path, int path_size)
{
    memset(host, 0, host_size);
    memset(path, 0, path_size);

    char* ptr;
    ptr = strstr(url, "//");
    if (ptr)
        ptr += 2;
    else
        ptr = url;

    strncpy(host, ptr, host_size - 1);    //如果 src 字元數比 count 少，會把剩下未滿 count 的部分通通補上 '\0'
    host[host_size - 1] = '\0';

    ptr = strchr(host, '/');
    if (ptr)
    {
        strncpy(path, ptr + 1, path_size - 1);
        path[path_size - 1] = '\0';
        *ptr = '\0';
    }

    ptr = strchr(host, ':');
    if (ptr)
        *ptr = '\0';
}

void search_link(char* url_file, char* link_buf)
{
    FILE* fptr = fopen(url_file, "r");
    if (!fptr)
    {
#ifdef DEBUG
        printf("---------------\nfile open fail !\n---------------\n");
#endif
        return;
    }

    struct stat fstat;
    stat(url_file, &fstat);
    int fsize = fstat.st_size;
    if (fsize <= 0)
    {
#ifdef DEBUG
        printf("---------------\nurl file empty !\n---------------\n");
#endif
        return;
    }

    char* file_buf = malloc(fsize);
    if (!file_buf)
    {
#ifdef DEBUG
        printf("---------------\nmalloc fail !\n---------------\n");
#endif
        return;
    }

    if (fread(file_buf, fsize, 1, fptr) != 1)
    {
#ifdef DEBUG
        printf("---------------\nfread error !\n---------------\n");
#endif
        return;
    }

    char host[MAX_URL_SIZE];
    char path[MAX_URL_SIZE];
    char link_file[MAX_NAME_SIZE];
    char* curr_ptr = link_buf;
    char* link_loc = strstr(file_buf, "href=\"http");

    while(link_loc)
    {
        link_loc += 6;
        char* link_end = strchr(link_loc, '\"');
        int link_size = link_end - link_loc;
        char link[link_size + 1];
        strncpy(link, link_loc, link_size);
        link[link_size] = '\0';
#ifdef DEBUG
        printf("link_loc: %p\t", link_loc);
        printf("link_end: %p\t", link_end);
        printf("link_size: %p  \t", link_size);
        printf("link: %s\n", link);
#endif
        get_host_n_path(link, host, MAX_URL_SIZE, path, MAX_URL_SIZE);
        make_file_name(link_file, host, path);

        FILE* fptr = fopen(link_file, "r+");
        if (!fptr)      //連結未重覆
        {
            fptr = fopen(link_file, "w+");
            strncpy(curr_ptr, padding, PADDING_SIZE);
            curr_ptr += PADDING_SIZE;
            strncpy(curr_ptr, link_loc, link_size);
            curr_ptr += link_size;
            *curr_ptr++ = '\n';
        }

        fclose(fptr);
        link_loc = strstr(link_loc, "href=\"http");
    }

#ifdef DEBUG
    printf("curr_ptr: %p\n", curr_ptr);
    printf("link_buf: %p\n", link_buf);
#endif
    link_buf[curr_ptr - link_buf] = '\0';

    free(file_buf);
}

