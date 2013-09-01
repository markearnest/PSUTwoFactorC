/* Two factor test
 * All this does is make a call to the twofactor DLL and prints the return code
 * Mark Earnest
 * 1/26/01
 */
#include <stdio.h>

int twofactor(char *dname, char *so, char *app, char *username, char *prn);

void main ()
{
	char dname[30];
	char so[5];
	char app[20];
	char username[10];
	char prn[10];
	printf("twofactortest 1.0\n\nEnter server, port, appid, username, and prn\n\n");
	scanf("%s", &dname);
	scanf("%s", &so);
	scanf("%s", &app);
	scanf("%s", &username);
	scanf("%s", &prn);
	printf("Return code is %i\n\n", twofactor(dname, so, app, username, prn));
}
