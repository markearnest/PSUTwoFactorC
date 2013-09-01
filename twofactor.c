/*
 * twofactor.c - Remote SecureID authentication with NCPASS
 * Mark Earnest (mxe20@psu.edu)
 * Last Revision - 4/09/02
 * Version 1.0
*/

#ifdef WIN32 /* Windows includes */
#include <winsock.h> 
#include <time.h>    
#else /* Unix includes */
#include <sys/types.h>
#include <sys/sockets.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#endif
#include <stdio.h> 
#include <stdlib.h>

#ifdef WIN32
#define DllExport  __declspec( dllexport )
#endif

/* Function Prototypes */
#ifdef WIN32
DllExport int twofactor(char *server_dname, char *server_port, char *appID, char *userID, char *secureID);
int twofactorprocessing (char *server_dname, char *server_port, char *appID, char *userID, char *secureID);
#endif
char ASCIItoEBCDIC(const unsigned char c);
char EBCDICtoASCII(const unsigned char c);
int build_header(char *, char *, char c);
void clear_array(char *);
void socket_close(int sc);

#ifdef WIN32
/* Multi-threading code */
/* This pretty much just creates a mutex lock that prevents more than one call to            
 *  twofactorprocessing at a time. Under normal circumstances this would be silly since we 
 *  are building this as a multithreaded DLL (compiler option /MD), however this DLL is called
 *  from Smalltalk, so all bets are off. This is what they use for the paymentmanager and other
 *	dlls that are called from Smalltalk, so this is how I did it. If performance ever becomes 
 *	an issue, it would help to remove this code, rename twofactorprocessing to twofactor and 
 *	and ensure that Smalltalk is handling it's own data in a thread-safe manner.
 * Also, I am working off of the assumption that if this code is called from Unix, it is NOT
 *  being called from Smalltalk, so this mutex is not needed. This is the reason for the #ifdef
 *  around all of this.
 *		-mark
*/
static CRITICAL_SECTION cs;
static BOOL init_criticalSection = FALSE;
DllExport int twofactor (char *server_dname, char *server_port, char *appID, char *userID, char *secureID)
{
		int returnCode = -1;
	/* Check for the Critical Section, if not init a Critical Section */
	if (init_criticalSection == FALSE)
	{	
		InitializeCriticalSection (&cs);
		init_criticalSection = TRUE;
	}
	/* Wait for Critical Section to be available */
	EnterCriticalSection (&cs);
	/* Do the processing */
 	returnCode = twofactorprocessing(server_dname, server_port, appID, userID, secureID);
	/* Release Critical Section */
	LeaveCriticalSection (&cs);
	return (returnCode);
}

/* twofactorprocessing function
 * Data passed (all char arrays)
 *   Server Domain Name
 *   Server Port
 *   Application ID (no max length)
 *   User ID (max 20 characters)
 *   Secure ID Number (max 16 characters)
 * Data Returned:
 *   Return Codes:
 *     0 - Authenticated
 *     1 - Not Authenticated
 *   Error Codes:
 *     10 - No winsock found
 *     20 - Winsock wrong version
 *     30 - Socket creation failed
 *     40 - Server domain name failed to resolve
 *     50 - Socket connect() failed
 *     60 - TLI header send failed
 *     65 - TLI header recieve failed
 *     70 - TLI auth request send failed
 *     75 - TLI auth request recieve failed
 * Variables:
 *   int:
 *     sd - socket
 *     x - generic loop counter
 *     tli_index - index for array
 *     tmp_index - temp index for array
 *     err - error code
 *   stort int:
 *     lPtr - pointer for array
 *   char:
 *     tli_stream - general purpose data stream array
 *     sysID - system ID (NCTLI)
*/  
int twofactorprocessing (char *server_dname, char *server_port, char *appID, char *userID, char *secureID) 
#else /* Unix entry point */
int twofactor(char *server_name, char *server_port, char *appID, char *userID, *secureID)
#endif
{
	/* init variables */
	char *sysID = "NCTLI";
	int sd;
	int unsigned x, returncode = 9;
	short int *lPtr;
	char tli_stream[100];
	int tli_index = 0, tmp_index = 0;
	char transID[7];
#ifdef WIN32 /* Winsocket socket structs and vars */
	struct sockaddr_in serverAddr;
	struct hostent *hPtr;
	fd_set fdset;
	WORD wVersionRequested;
	WSADATA wsaData;
#else /* UNIX socket structs and vars */
	struct sockaddr_in localAddr, servAddr;
	struct hostend *host;
#endif

	/* Generate transaction ID */
	/* I'm not totally sure that this is required to be a random number (or any special value)
	 *	It couldn't hurt to make it a little random since NCPASS couldn't even completly explain
	 *	what thus value is used for
	*/
#ifdef WIN32
	srand( (unsigned int)time( (time_t *)NULL ) ); 
	for (x = 0; x < 6; x++)
		itoa((rand() * 9 / (RAND_MAX + 1)), &transID[x], 10);
#else
	/* TODO: fix this so it generates a random number for Unix (there is no itoa in Unix) */
	transID[0] = 0;
	transID[1] = 1;
	transID[2] = 2;
	transID[3] = 3;
	transID[4] = 4;
	transID[5] = 5;
#endif

#ifdef WIN32 /* Windows socket preperation */

	/* initialize the socket descriptor set */
	FD_ZERO(&fdset);
	wVersionRequested = MAKEWORD(1,1);
	if((WSAStartup(wVersionRequested, &wsaData)) != 0)
		return 10;
	
	/* Confirm Winsock DLL supports 1.1 */
	if (LOBYTE(wsaData.wVersion) != 1 ||
		HIBYTE(wsaData.wVersion) != 1) {
		return 20;
	}

	/* Create a socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		return 30;
	}
	
	/* Set up server address to use */
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) atoi(server_port));
	hPtr = gethostbyname(server_dname);
	if (hPtr == NULL) {
		return 40;
	}
	serverAddr.sin_addr.s_addr = ((struct in_addr *) (hPtr->h_addr))->s_addr;

#else /* Unix socket preperation */

	/* get host IP address */
	host = gethostbyname(server_dname);
	if (host = NULL)
		return 40;
	
	/* Generate socket info */
	servAddr.sin_family = host->h_addrtype;
	memcpy((char *) &servAddr.sin_addr.s.addr, host->h_addr_list[0], host->h_length);
	servAddr.sin_port = htons(atoi(server_port));

	/* Create Socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) 
		return 30;

	/* Bind to local port */
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(0);
	if ((bind(sd, (struct sockaddr *) &localAddr, sizeof(localAddr))) < 0)
		return 42;
#endif

	/* Connect to remote host */
	if (connect(sd, (const struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
		socket_close(sd);
		return 50;
	}

	clear_array(tli_stream);
	
	/* build header - process code 0 */
	tli_index = build_header(tli_stream, transID, '0'); 
		
	/* Application ID */
	tmp_index = tli_index;
	tli_index++;
	tli_index++;
	for (x = 0; x < strlen(appID); x++)
	{
		tli_stream[tli_index] = ASCIItoEBCDIC(appID[x]);
		tli_index++;
	}
	lPtr = (short *) &tli_stream[tmp_index]; 		
	*lPtr = htons((short) strlen(appID));

	
	/* System ID */
	tmp_index = tli_index;
	tli_index++;
	tli_index++;
	for (x = 0; x < strlen(sysID); x++)
	{
		tli_stream[tli_index] = ASCIItoEBCDIC(sysID[x]);
		tli_index++;
	}
	lPtr = (short *) &tli_stream[tmp_index]; 		
	*lPtr = htons((short) strlen(sysID));

	/* Password for EXIT45 *not used* */
	tli_stream[tli_index] = 0;
	tli_index++;
	tli_stream[tli_index] = 0;
	tli_index++;

	/* Direction ID */
	tli_stream[tli_index] = 0;
	tli_index++;
	tli_stream[tli_index] = 1;
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('1');
	tli_index++;

	/* Length of data stream */
	lPtr = (short *) &tli_stream[0];
	*lPtr = htons((short) tli_index);

#ifndef WIN32
	tli_index++;
#endif

	/* Send handshake */	
	if(send(sd, tli_stream, tli_index, 0) < 0) {
		socket_close(sd);
		return 60;
	}

	clear_array(tli_stream);
	
	/* Recieve response */
	if(recv(sd, tli_stream, 100, 0) < 0) {
		socket_close(sd);
		return 65;
	}

	clear_array(tli_stream);
	
	/* build header - process code 3 */
	tli_index = build_header(tli_stream, transID,'3'); 

	/* User ID */
	tmp_index = tli_index;
	tli_index++;
	tli_index++;
	for (x = 0; x < strlen(userID); x++)
	{
		tli_stream[tli_index] = ASCIItoEBCDIC(userID[x]);
		tli_index++;
	}
	lPtr = (short *) &tli_stream[tmp_index]; 		
	*lPtr = htons((short) strlen(userID));

	/* Remote User (not used) */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 

	/* Current Password (not used) */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 

	/* Token challenge (not used) */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 

	/* Token response (SecureID number)  */
	tmp_index = tli_index;
	tli_index++;
	tli_index++;
	for (x = 0; x < strlen(secureID); x++)
	{
		tli_stream[tli_index] = ASCIItoEBCDIC(secureID[x]);
		tli_index++;
	}
	lPtr = (short *) &tli_stream[tmp_index]; 		
	*lPtr = htons((short) strlen(secureID));

	/* Token serial number (not used) */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 

	/* Token type  (11 = SDA SecureID standard)  */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 2;   
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 11;
	tli_index++; 

	/* New token challenge (not used) */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 

	/* New token response (not used) */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 

	/* P card PIN (not used) */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 

	/* Requestor ID ('TCP') */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 3;
	tli_index++; 
	tli_stream[tli_index] = ASCIItoEBCDIC('T');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('C');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('P');
	tli_index++;

	/* Terminal/node ('WEBTERM') */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 7;
	tli_index++; 
	tli_stream[tli_index] = ASCIItoEBCDIC('W');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('E');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('B');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('T');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('E');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('R');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('M');
	tli_index++;

	/* Target (not used) */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 0;
	tli_index++; 

	/* Target supplementary ('TLI') */
	tli_stream[tli_index] = 0;
	tli_index++; 
	tli_stream[tli_index] = 3;
	tli_index++; 
	tli_stream[tli_index] = ASCIItoEBCDIC('T');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('L');
	tli_index++;
	tli_stream[tli_index] = ASCIItoEBCDIC('I');
	tli_index++;

	tli_stream[tli_index] = 0;
	tli_index++;

	/* Length of data stream */
	lPtr = (short *) &tli_stream[0];
	*lPtr = htons((short) tli_index);

#ifndef WIN32
	tli_index++;
#endif

	/* Send auth request */
	if(send(sd, tli_stream, tli_index, 0) < 0) {
		socket_close(sd);
		return 70;
	}

	clear_array(tli_stream);

	/* Recieve auth response */
	if(recv(sd, tli_stream, 100,0) < 0) {
		socket_close(sd);
		return 75;
	}

	/* Check byte 21 (authentication result) for a non-zero condition
	 * NOTE: The NSPASS TLI function does not return anything to indicate why the 
	 * authentication failed (ie token expired, account locked, etc).
	 */
	if (tli_stream[21] != 0)
		returncode = 1;
	else 
		returncode = 0;
	/*
	for (tli_index = 0;tli_index < 100;tli_index++) {
		putchar(EBCDICtoASCII(tli_stream[tli_index]));
	}
	*/
	socket_close(sd);
	return returncode;
}

/* build_header
 * Builds the data stream header
 * Data passed:
 *   hdr - pointer to tli_stream array
 *   tid - pinter to transID
 *   c - process code
 * Data returned:
     integer - tli_index pointer
 * Variables:
 *   int saddr - initial pointer location
 *   int x - counter
*/
int build_header(char *hdr, char *tid ,char c)
{
	int x;
	int saddr = (int) hdr;  /* starting address */	
	hdr++;              /* Skip 2 chars (used later for byte count) */ 
	hdr++;
		
	/* "OS" */	
	*hdr = ASCIItoEBCDIC('O');
	hdr++;
	*hdr = ASCIItoEBCDIC('S');
	hdr++;

	/* Transaction ID */

	for (x = 0; x < 6; x++)
	{
		*hdr = ASCIItoEBCDIC(*tid);
		hdr++;
		tid++;
	}

	/* "SE" */
	*hdr = ASCIItoEBCDIC('S');
	hdr++;
	*hdr = ASCIItoEBCDIC('E');
	hdr++;
	
	/* Process code */
	*hdr = ASCIItoEBCDIC('0');
	hdr++;
	*hdr = ASCIItoEBCDIC(c);
	hdr++;

	return (int) hdr - saddr;
}

/* ASCIItoEBCDIC
 * Convet a single character from ASCII to EBCDIC
 * Data passed:
 *   c - single character to be converted
 * Data returned:
 *   converted character
*/
char ASCIItoEBCDIC(const unsigned char c)
{
	static unsigned char a2e[256] = {
          0,  1,  2,  3, 55, 45, 46, 47, 22,  5, 37, 11, 12, 13, 14, 15,
         16, 17, 18, 19, 60, 61, 50, 38, 24, 25, 63, 39, 28, 29, 30, 31,
         64, 79,127,123, 91,108, 80,125, 77, 93, 92, 78,107, 96, 75, 97,
        240,241,242,243,244,245,246,247,248,249,122, 94, 76,126,110,111,
        124,193,194,195,196,197,198,199,200,201,209,210,211,212,213,214,
        215,216,217,226,227,228,229,230,231,232,233, 74,224, 90, 95,109,
        121,129,130,131,132,133,134,135,136,137,145,146,147,148,149,150,
        151,152,153,162,163,164,165,166,167,168,169,192,106,208,161,  7,
         32, 33, 34, 35, 36, 21,  6, 23, 40, 41, 42, 43, 44,  9, 10, 27,
         48, 49, 26, 51, 52, 53, 54,  8, 56, 57, 58, 59,  4, 20, 62,225,
         65, 66, 67, 68, 69, 70, 71, 72, 73, 81, 82, 83, 84, 85, 86, 87,
         88, 89, 98, 99,100,101,102,103,104,105,112,113,114,115,116,117,
        118,119,120,128,138,139,140,141,142,143,144,154,155,156,157,158,
        159,160,170,171,172,173,174,175,176,177,178,179,180,181,182,183,
        184,185,186,187,188,189,190,191,202,203,204,205,206,207,218,219,
        220,221,222,223,234,235,236,237,238,239,250,251,252,253,254,255};
	return a2e[c];
}

/* EBCDICtoASCII
 * Convert a single character from EBCDIC to ASCII
 * See above function
*/
char EBCDICtoASCII(const unsigned char c)
{
static unsigned char e2a[256] = {
          0,  1,  2,  3,156,  9,134,127,151,141,142, 11, 12, 13, 14, 15,
         16, 17, 18, 19,157,133,  8,135, 24, 25,146,143, 28, 29, 30, 31,
        128,129,130,131,132, 10, 23, 27,136,137,138,139,140,  5,  6,  7,
        144,145, 22,147,148,149,150,  4,152,153,154,155, 20, 21,158, 26,
         32,160,161,162,163,164,165,166,167,168, 91, 46, 60, 40, 43, 33,
         38,169,170,171,172,173,174,175,176,177, 93, 36, 42, 41, 59, 94,
         45, 47,178,179,180,181,182,183,184,185,124, 44, 37, 95, 62, 63,
        186,187,188,189,190,191,192,193,194, 96, 58, 35, 64, 39, 61, 34,
        195, 97, 98, 99,100,101,102,103,104,105,196,197,198,199,200,201,
        202,106,107,108,109,110,111,112,113,114,203,204,205,206,207,208,
        209,126,115,116,117,118,119,120,121,122,210,211,212,213,214,215,
        216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,
        123, 65, 66, 67, 68, 69, 70, 71, 72, 73,232,233,234,235,236,237,
        125, 74, 75, 76, 77, 78, 79, 80, 81, 82,238,239,240,241,242,243,
         92,159, 83, 84, 85, 86, 87, 88, 89, 90,244,245,246,247,248,249,
         48, 49, 50, 51, 52, 53, 54, 55, 56, 57,250,251,252,253,254,255};
	return e2a[c];
}

/* clear_array
 * fills array with 'F' characters
 * Data passed:
 *   c - character array
 * nothing returned
*/
void clear_array(char *c)
{
	int x;
	for (x = 0; x <100; x++) 
	{
		*c = 'F';
		c++;
	}
}

void socket_close (int sd) 
{
	/* Shutdown socket */
	shutdown(sd, 2);

	/* Close socket */
	closesocket(sd);

	/* Perform socket cleanup */
	WSACleanup();
}

