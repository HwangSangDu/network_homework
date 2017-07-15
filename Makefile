
#common.h belong to all header file 
main : main.o packet.o 

		gcc -g -o main main.o packet.o -lpcap

main.o : packet.h main.c
		gcc -g -c -o main.o main.c

packet.o : packet.h packet.c
		gcc -g -c -o packet.o packet.c

		gcc -o main main.o packet.o -lpcap

main.o : packet.h main.c
		gcc -c -o main.o main.c

packet.o : packet.h packet.c
		gcc -c -o packet.o packet.c

clean :
		rm *.o
