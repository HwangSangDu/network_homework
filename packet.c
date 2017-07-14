/*
fuction group about packet
*/

#include "packet.h"



/*
u_char* my_strncpy(u_char* d, const u_char* s, int len)
{
u_int i;
d = malloc(sizeof(u_char) * (len + 1));
for (i = 0; i < len; ++i)
d[i] = s[i];
d[len] = '\0';
return d;
}
//*/
///*
u_char* my_memcpy(u_char* d, const u_char* s, int len)
{
	int i;
	//d = (u_char *)malloc(sizeof(u_char) * (len + 1));
	for (i = 0; i < len; ++i)
		d[i] = s[i];
	return d;
}
//*/
///*
void str_to_hex_print(u_char* str , int len)
{
	int i;
	//printf("%d\n",sizeof(str));
	for (i = 0; i < len ; i++)
		printf("%02x", str[i]);
	printf("\n");
}
//*/


