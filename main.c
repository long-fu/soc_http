#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "http_parser.h"

#include <netdb.h>


#include "http_parser.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

//https
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
 

// #include <tpf/tpfeq.h>
// #include <tpf/tpfio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* define HOME to be dir for key and certificate files... */
#define HOME "/certs/"
/* Make these what you want for certificate & key files */
#define CERT_FILE  HOME "1024ccert.pem"
#define KEY_FILE  HOME  "1024ckey.pem"

/*Cipher list to be used*/
#define CIPHER_LIST "AES128-SHA"

/*Trusted CAs location*/
#define CA_FILE "/certs/1024ccert.pem"
#define CA_DIR  NULL

/*Password for the key file*/
#define KEY_PASSWD "keypass"

#define IP "9.57.13.156"

#define PORT "1111"


void QSSN(void)
{
int socketfd;
int err, count;
char buff[32];
struct sockaddr_in socketaddr;

/*SSL PART*/
SSL_METHOD *meth;
SSL_CTX *ctx;
SSL *myssl;

socketfd=socket(AF_INET,SOCK_STREAM,0);

socketaddr.sin_family=AF_INET;
socketaddr.sin_addr.s_addr=inet_addr(IP);
socketaddr.sin_port=atoi(PORT);

/* SSL Part*/
SSL_library_init();
SSL_load_error_strings();

meth=SSLv23_client_method();

/*Create a new context block*/
ctx=SSL_CTX_new(meth);
if (!ctx) {
   printf("Error creating the context.\n");
   exit(0);
}

/*Set cipher list*/
if (SSL_CTX_set_cipher_list(ctx,CIPHER_LIST) <= 0) {
printf("Error setting the cipher list.\n");
   exit(0);
}

/*Indicate the certificate file to be used*/
if (SSL_CTX_use_certificate_file(ctx,CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
   printf("Error setting the certificate file.\n");
   exit(0);
}

/*Load the password for the Private Key*/
SSL_CTX_set_default_passwd_cb_userdata(ctx,KEY_PASSWD);

/*Indicate the key file to be used*/
if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
   printf("Error setting the key file.\n");
   exit(0);
}

/*Make sure the key and certificate file match*/
if (SSL_CTX_check_private_key(ctx) == 0) {
   printf("Private key does not match the certificate public key\n");
   exit(0);
}

/* Set the list of trusted CAs based on the file and/or directory provided*/
if(SSL_CTX_load_verify_locations(ctx,CA_FILE,CA_DIR)<1) {
   printf("Error setting verify location\n");
   exit(0);
}

/* Set for server verification*/
SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

/*Create new ssl object*/
myssl=SSL_new(ctx);

if(!myssl) {
   printf("Error creating SSL structure.\n");
   exit(0);
}

/* Connect to the server, TCP/IP layer,*/
err=connect(socketfd,(struct sockaddr*)&socketaddr,sizeof(socketaddr));
if(err<0) {
   printf("Socket returned error #%d,program terminated\n",sock_errno());
   SSL_free(myssl);
   SSL_CTX_free(ctx);
   exit(0);
}

/*Bind the socket to the SSL structure*/
SSL_set_fd(myssl,socketfd);

/*Connect to the server, SSL layer.*/
err=SSL_connect(myssl);

/*Check for error in connect.*/
if (err<1) {
   err=SSL_get_error(myssl,err);
   printf("SSL error #%d in accept,program terminated\n",err);

   if(err==5){printf("sockerrno is:%d\n",sock_errno());}
  
   close(socketfd);
   SSL_free(myssl);
   SSL_CTX_free(ctx);
   exit(0);
}

/*Print out connection details*/
printf("SSL connection on socket %x,Version: %s, Cipher: %s\n",
       socketfd,
       SSL_get_version(myssl),
       SSL_get_cipher(myssl));

/*Send message to the server.*/
err=SSL_write(myssl,"Hello there!!!!",sizeof("Hello there!!!!")+1);
/*Check for error in write.*/
if(err<1) {
   err=SSL_get_error(myssl,err);
   printf("Error #%d in write,program terminated\n",err);
   /********************************/
   /* If err=6 it means the Server */
   /* issued an SSL_shutdown. You  */
   /* must respond with a shutdown */
   /* to complete a graceful       */
   /* shutdown                     */
   /********************************/
   if(err==6)
     SSL_shutdown(myssl);
   SSL_free(myssl);
   close(socketfd);
   SSL_CTX_free(ctx);
   exit(0);
}

/*Read servers response.*/
err = SSL_read (myssl, buff, sizeof(buff));
/*Check for error in read.*/
if(err<1) {
   err=SSL_get_error(myssl,err);
   printf("Error #%d in read,program terminated\n",err);
   /********************************/
   /* If err=6 it means the client */
   /* issued an SSL_shutdown. You */
   /* must respond with a shutdown */
   /* to complete a graceful */
   /* shutdown */
   /********************************/
   if(err==6)
     SSL_shutdown(myssl);
    SSL_free(myssl);
    close(socketfd);
    SSL_CTX_free(ctx);
    exit(0);
}

printf("Server said: %s\n",buff);

err=SSL_shutdown(myssl);
count = 1;
/***********************************/
/* Try SSL_shutdown() 5 times to   */
/* wait for the remote application */
/* to issue SSL_shutdown().        */
/***********************************/

while(err != 1) {
   err=SSL_shutdown(myssl);
   if(err != 1)
     count++;
   if (count == 5)
     break;
   sleep(1);
}

if(err<0)
   printf("Error in shutdown\n");
else if(err==1)
   printf("Client exited gracefully\n");

close(socketfd);
SSL_free(myssl);
SSL_CTX_free(ctx);
exit(0);
}

extern const char *SSL_get_cipher(SSL *ssl);
/* 8 gb */
static const int64_t kBytes = 8LL << 30;


static int on_info(http_parser* p) {
  printf("on_info %d\r\n",p->flags);
  return 0;
}


static int on_headers_complete(http_parser* p) {
  printf("on_headers_complete %d\r\n",p->method);
  return 0;
}

static int on_message_complete(http_parser* p) {
  printf("on_message_complete %s\r\n",(char*)p->data);
  return 0;
}

static int on_data(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("on_data type: %d %s==%zu\r\n",p->type,buffer,length);
    return 0;
}

static int on_header_field(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("%s: ",buffer);
    return 0;
}

static int on_header_value(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("%s\r\n",buffer);
    return 0;
}

static int on_url(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("on_url %s\r\n",buffer);
    return 0;
}

static int on_status(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("on_status %s\r\n",buffer);
    return 0;
}

static int on_body(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("on_body %s\r\n",buffer);
    return 0;
}

static http_parser_settings settings = {
  .on_message_begin = on_info,
  .on_headers_complete = on_headers_complete,
  .on_message_complete = on_message_complete,
  .on_header_field = on_header_field,
  .on_header_value = on_header_value,
  .on_url = on_url,
  .on_status = on_status,
  .on_body = on_body
};

struct http_parser parser_response;
int is_init = 0;

int
parser_responder(char *data,size_t data_len)
{
    size_t parsed;
    if (is_init == 0) 
    {
        http_parser_init(&parser_response, HTTP_RESPONSE);
        is_init = 1;
    }
    parsed = http_parser_execute(&parser_response, &settings, data, data_len - 1);
        
    if (parsed == data_len) {
        printf("解析成功 %zu",parsed);
    } else {
        printf("解析失败  %zu", parsed);
    }
    printf("解析一次最后返回");
    
    return 0;
}

static int sock = 0;

int 
on_recive_request(const char *url,const int port, const char *http_heads) 
{
    int sock,n;
    struct hostent *hent;
    
    struct sockaddr_in servaddr = { 0 };

    char ip_address[32] = { 0 };
    
    char rbuf[2048] = { 0 };
    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock < 0) {
        perror("tcp creat error");
        exit(1);
    }
    
    printf("请求地址 %s\r\n",url);

    if((hent=gethostbyname(url))==NULL){
        perror("ip error");
        exit(2);
    }

    {
        int32_t ipi = 0;
        ipi = (*(*hent->h_addr_list + 3) << 24) & 0xFF000000;
        ipi |= ((*(*hent->h_addr_list + 2) << 16)  & 0xFF0000);
        ipi |= ((*(*hent->h_addr_list + 1) << 8) & 0xFF00);
        ipi |= ((*(*hent->h_addr_list + 0) << 0) & 0xFF);
        printf("ip地址 0x%x \n",ipi);//这也是正确的ip地址流 对位操作的时候需要知道 大小端 熟悉指针操作
    }
    //获取到网络类型 ipv4 ipv6 两个类型 网络地址族
    printf("协议族类型 %d\n",hent->h_addrtype);
    
    //解析出 点分 地址
    //网络字节流 ——》IP字符串 0.0.0.0
    if (inet_ntop(hent->h_addrtype,(void *)hent->h_addr_list[0],ip_address,sizeof(ip_address)) == NULL) {
        perror("inet_ntop error");
        exit(4);
    }
    printf("IP address %s \r\n", ip_address);
    //IP字符串 ——》网络字节流
    if(inet_pton(hent->h_addrtype,ip_address,&servaddr.sin_addr) <= 0){
        perror("inet_pton error");
        exit(5);
    }
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    
    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect error\n");
        exit(6);
    }
    
    int result = write(sock, http_heads, strlen(http_heads));
    
    if (result != strlen(http_heads)) {
        perror("数据写入失败");
        exit(-1);
    }
    
    printf("开始接受数据 %d\r\n",sock);

    int ri = 0;
    while ((n = read(sock, rbuf, 2048))>0) {
        rbuf[n] = 0;
        printf("%d 接受的数据 %s \r\n",ri ,rbuf);
        parser_responder(rbuf,strlen(rbuf));
        ri ++;
    }
    close(sock);
    printf("数据接收完成 %d", n);
    return 0;
} 

int test_http() {
      char hostname[] = "www.objc.io";

    char host_header[] = "GET /about.html HTTP/1.1\r\n\
Host: www.objc.io\r\n\
Accept-Encoding: gzip, deflate\r\n\
Connection: keep-alive\r\n\
If-None-Match: \"a54907f38b306fe3ae4f32c003ddd507\"\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
If-Modified-Since: Mon, 10 Feb 2014 18:08:48 GMT\r\n\
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.74.9 (KHTML, like Gecko) Version/7.0.2 Safari/537.74.9\r\n\
Referer: http://www.objc.io/\r\n\
DNT: 1\r\n\
Accept-Language: en-us\r\n\r\n";
   int port = 80;
   on_recive_request(hostname,port,host_header);
   return 0;
}

int test_https() 
{

  SSL *ssl = NULL;
  SSL_CTX *ctx = NULL;
  const SSL_METHOD *client_method;
  X509 *server_cert;
  int sd,err;
  char *str,outbuf[4096],inbuf[4096];
      
      char hostname[] = "www.objc.io";

    char host_header[] = "GET /about.html HTTP/1.1\r\n\
Host: www.objc.io:443\r\n\
Accept-Encoding: gzip, deflate\r\n\
Connection: keep-alive\r\n\
If-None-Match: \"a54907f38b306fe3ae4f32c003ddd507\"\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
If-Modified-Since: Mon, 10 Feb 2014 18:08:48 GMT\r\n\
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.74.9 (KHTML, like Gecko) Version/7.0.2 Safari/537.74.9\r\n\
Referer: http://www.objc.io/\r\n\
DNT: 1\r\n\
Accept-Language: en-us\r\n\r\n";

  struct hostent *host_entry;
  struct sockaddr_in server_socket_address;
  struct in_addr ip;

  /* (1) 初始化openssl库 */
  SSL_library_init();

//   OPENSSL_init();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  client_method = SSLv23_client_method( );
  ctx = SSL_CTX_new(client_method);
  if (!ctx) {
    // fprintf (stderr, "SSL_CTX_new failed:\n");
    // ERR_print_errors_fp (stderr);
    // perror(stderr);
    perror("SSL_CTX_new failed:\n");
    return 0;
  }
  printf("(1) SSL context initialized\n\n");

  /* (2) 把域名转换成ip地址 */
    host_entry = gethostbyname(hostname);
    if (!host_entry) 
    {
      perror("gethostbyname failed:\n");
      return 0;
  
   }
  bcopy(host_entry->h_addr, &(ip.s_addr), host_entry->h_length);
  printf("(2) '%s' has IP address '%s'\n\n", hostname, inet_ntoa(ip));
  
  /* (3) 用tcp连接到server的443端口 */
  sd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&server_socket_address, '\0', sizeof(server_socket_address));
  server_socket_address.sin_family = AF_INET;
  server_socket_address.sin_port = htons(443);
  memcpy(&(server_socket_address.sin_addr.s_addr),
      host_entry->h_addr, host_entry->h_length);
  err = connect(sd, (struct sockaddr*) &server_socket_address,
      sizeof(server_socket_address));
  if (err < 0) { perror("can't connect to server port"); exit(1); }
  printf("(3) TCP connection open to host '%s', port %d\n\n",
      hostname, server_socket_address.sin_port);

  /* (4) 在tcp连接上进行ssl握手 */
  ssl = SSL_new(ctx); /* 创建ssl句柄 ，之后的send，recv都在ssl句柄上进行 */
  if (!ssl) {
    // fprintf (stderr, "SSL_new failed:\n");
    perror ("SSL_new failed:");
    return 0;
  }

  SSL_set_fd(ssl, sd); /* 把ssl句柄绑定到scoket */
  err = SSL_connect(ssl); /* 启动ssl握手 */
  printf("(4) SSL endpoint created & handshake completed\n\n");

  /* (5) 打印出协商的好的加密密文 */
//   printf("(5) SSL connected with cipher: %s\n\n", SSL_get_cipher(ssl));
printf("(5) SSL connection on socket %x,Version: %s, Cipher: %s\n",
       sd,
       SSL_get_version(ssl),
       SSL_get_cipher(ssl));

  /* (6) 打印服务器的证书  */
  server_cert = SSL_get_peer_certificate(ssl);
  if (server_cert == NULL) 
  {
      perror ("SSL_get_peer_certificate failed:");
      return 0;
  }
  printf("(6) server's certificate was received:\n\n");
  str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
  printf("  subject: %s\n", str);
  str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
  printf("  issuer: %s\n\n", str);
  /* 这里对证书进行验证 */
  X509_free(server_cert);

  /* (7) 握手完成 --- 开始在ssl上发送http请求 */
//   sprintf(host_header,"Host: %s:443\r\n",hostname);
//   strcpy(outbuf,"GET / HTTP/1.1\r\n");
//   strcat(outbuf,host_header);
//   strcat(outbuf,"Connection: close\r\n");
//   strcat(outbuf,"\r\n");
  err = SSL_write(ssl, host_header, strlen(host_header));
  shutdown (sd, 1); /* send EOF to server */
  printf("(7) sent HTTP request over encrypted channel:\n\n%s\n",host_header);


  /* (8) 通过ssl句柄读取服务器响应 */
  printf ("(8) got back %d bytes of HTTP response:\n",sd);
  do{
    memset(inbuf, 0, sizeof(inbuf));
    err = SSL_read(ssl, inbuf, sizeof(inbuf) - 1);
    printf ("%s",inbuf);
    inbuf[err] = '\0';
  }while(err > 0);
  /* (9) 释放连接，句柄 */
  SSL_shutdown(ssl);
  close(sd);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  printf("(9) all done, cleaned up and closed connection\n\n");
    return 0;
}

int main(int argc, char** argv)
{
    // test_http();
    test_https();
    // QSSN();
}
