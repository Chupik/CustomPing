//
//  main.cpp
//  CustomPing
//
//  Created by Alexandr on 10.04.15.
//  Copyright (c) 2015 Alexandr. All rights reserved.
//

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>

#define PROCEDURE

struct sigaction sigIntHandler;

//ДЕКЛАРАЦИИ
//заголовок IP-датаграммы
struct IPHEADER
{
    unsigned char version;          //1     1   версия ip-протокола
    unsigned char typeOfService;    //1     2   TOS
    unsigned short length;          //2     4   длина датаграммы
    unsigned short id;              //2     6   идентификатор
    unsigned short flags;           //2     8   флаги
    unsigned char timeToLeave;      //1     9   время ожидания
    unsigned char protocol;         //1     10  тип протокола
    unsigned short checksum;        //2     12  чексумма
    unsigned int sourceIP;          //4     16  ip отправителя
    unsigned int destIP;            //4     20  ip назначения
};

//заголовок ICMP-датаграммы
struct ICMPHEADER
{
    unsigned char type;         //тип                       1   21
    unsigned char code;         //код                       2   22
    unsigned short checksum;    //чексумма по RFC 1071      4   24
    unsigned short id;          //идентификатор процесса    6   26
    unsigned short seqNumber;   //номер пакета порядковый   8   28
} __attribute__((packed));

//структура сообщения ICMP
struct ICMPREQUEST
{
    ICMPHEADER header;
    timeval time;                                      //      4  32
} __attribute__((packed));

//структура для исходящего сообщения
struct ICMPPACKET
{
    ICMPREQUEST icmpRequest;
};

//структура для входящего сообщения (приделан IP-заголовок)
struct ICMPINPACKET
{
    IPHEADER ipHeader;
    ICMPREQUEST icmpRequest;
};

//процедура вычисления чексуммы по RFC 1071
PROCEDURE long getChecksum(unsigned char *addr, int count)
{
    /* Расчет контрольной суммы Internet для count байтов,
     * начиная с addr.
     */
    //декларации
    unsigned int sum = 0;                   //переменная для хранения чексуммы
    
    printf(" *Процедура getChecksum\n");
    
    while( count > 1 )  {
        /*  складываем по два байта */
        sum += (*addr << 8) + *(addr + 1);
        addr += 2;
        count -= 2;
    }
    
    /*  сколько раз был перенос, столько и прибавляем */
    sum += (sum >> 16);
    
    sum = ~sum & 0xffff;
    
    sum = sum << 8;
    sum += sum >> 16;
    
    return sum & 0xffff;
}

//процедура формирования заголовка ICMP
PROCEDURE void setupOutPacket(ICMPPACKET *packet, unsigned short seqNumber)
{
    //декларации
    timeval requestTime;                                //структура для хранения времени запроса
    
    printf(" *Процедура setOutPacket\n");
    
    gettimeofday(&requestTime, DST_NONE);               //получаем текущее время
    
    packet->icmpRequest.header.checksum = 0;            //перед вычислением чексуммы, она должны быть установлена в ноль
    packet->icmpRequest.header.code = 0;                //код 0 - для эхо-запроса не нужен код
    packet->icmpRequest.header.id = getpid();           //в качестве идентификатора рекомендуется указывать ID процесса
    packet->icmpRequest.header.type = 8;                //тип 8 - эхо запрос
    
    packet->icmpRequest.header.seqNumber = seqNumber;   //номер в последовательности по порядку
    packet->icmpRequest.header.checksum = 0;
    packet->icmpRequest.time = requestTime;             //устанавливаем timestamp
    packet->icmpRequest.header.checksum = getChecksum((unsigned char *)&packet->icmpRequest, sizeof(packet->icmpRequest));
    //вычисляем чексумму
}

//процедура, печатающая содержимое ICMP датаграммы
PROCEDURE void printPacket(ICMPPACKET *packet)
{
    printf(" *Процедура printPacket\n");
    printf(" OUT:\n req type: %i\n req code: %i\n seq number: %i\n req time: %li\n", packet->icmpRequest.header.type, packet->icmpRequest.header.code, packet->icmpRequest.header.seqNumber, packet->icmpRequest.time.tv_sec);
}

//процедура, печатающая содержимое ICMP датаграммы
PROCEDURE void printPacket(ICMPINPACKET *packet)
{
    printf(" *Процедура printPacket\n");
    printf(" IN:\n req type: %X\n req code: %X\n seq number: %i\n req time: %li\n", packet->icmpRequest.header.type, packet->icmpRequest.header.code, packet->icmpRequest.header.seqNumber, packet->icmpRequest.time.tv_sec);
}

//процедура завершения программы
PROCEDURE void myfinish()
{
    printf(" *Программа завершила свою работу, system time: %li\n", time(0));
    _exit(1);
}

//процедура обработки и вывода ошибки
PROCEDURE void serveError()
{
    printf(" *Процедура serveError\n");
    printf(" ERROR: %s\n", strerror(errno));
    myfinish();
}

//процедура единичного пинга
PROCEDURE int onePing(int rawSocket, sockaddr_in *destAddr, int seqn)
{
    //декларации
    ICMPPACKET outPacket;                       //исходящая датаграмма
    ICMPINPACKET inPacket;                      //входящая датаграмма
    sockaddr_in sourceAddr;                     //адрес отправителя
    socklen_t adrSize = sizeof(sourceAddr);     //размер структуры адреса
    timeval responseTime;                       //структура хранения времени ответа
    double rqTime;                              //временные переменные хранения времени
    double rpTime;                              //временные переменные хранения времени
    
    printf(" *Процедура onePing\n");
    
    setupOutPacket(&outPacket, seqn);                                           //устанавливаем значения датаграммы
    
    if (sendto(rawSocket, (void *)&outPacket, sizeof(outPacket), 0, (sockaddr *)destAddr, sizeof(destAddr)) == -1)  //посылаем
    {
        serveError();       //обслуживаем ошибку
        return 0;
    }
    
    
    if (recvfrom(rawSocket, (void *)&inPacket, sizeof(inPacket), 0, (sockaddr *)&sourceAddr, &adrSize) == -1)       //получаем
    {
        serveError();       //обслуживаем ошибку
        return 0;
    }
    
    
    gettimeofday(&responseTime, DST_NONE);
    rqTime = outPacket.icmpRequest.time.tv_sec + outPacket.icmpRequest.time.tv_usec / 1000.;    //получаем секунды
    rpTime = responseTime.tv_sec + responseTime.tv_usec / 1000.;                                //получаем милисекунды
    
    printPacket(&outPacket);                                                                    //печатаем отладку
    printPacket(&inPacket);                                                                     //печатаем отладку
    printf(" ping time: %f s\n", rpTime - rqTime);
    
#ifdef DEBUG_IP_HEADER
    printf(" IP vers: v%X\n IP HEADER SIZE: %li\n ICMP HEADER SIZE: %li\n ICMP_MESSAGE_SIZE: %li\n TOTAL PACKET SIZE: %li\n CURRENT TIME: %li\n", inPacket.ipHeader.version & 0xf0 >> 2, sizeof(inPacket.ipHeader), sizeof(inPacket.icmpRequest.header), sizeof(inPacket.icmpRequest), sizeof(inPacket), time(0));                                      //отладка
#endif
    
    sleep(1);
    return 1;
}

//процедура continious ping
PROCEDURE void continiousPing(int rawSocket, sockaddr_in *destAddr)
{
    printf(" *Процедура continiousPing\n");
    for (int i = 0; true; i++)
    {
        if (onePing(rawSocket, destAddr, i) == 0)
        {
            //повтор, на случай, если не сработал ARP
            if (onePing(rawSocket, destAddr, i) == 0)
                serveError();
        }
    }
}

//процедура обработки прерывания программы
PROCEDURE void my_handler(int s){
    printf("Caught signal %d\n",s);
    myfinish();
}

//процедура проверки исходных данных
PROCEDURE int mystart(sockaddr_in *destAddr, int argc, const char * argv[], int &rawSocket)
{
    //декларации
    timeval timeOut;    //структура для хранения времени
    const char *addrName;   //строка с адресом
    
    printf(" *Процедура mystart\n");
    
    printf("Программа PING для Linux. Версия 0.1 alpha. Автор: Кочупалов Александр.\n");
    
    sigIntHandler.sa_handler = my_handler;      //процедуры
    sigemptyset(&sigIntHandler.sa_mask);        //отлова
    sigIntHandler.sa_flags = 0;                 //прерывания
    sigaction(SIGINT, &sigIntHandler, NULL);    //через ctrl-c
    
    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);                        //получаем дескриптор сокета и создаем его
    
    timeOut.tv_sec = 3;                                                         //устанавливаем таймаут ожидания блокирующего сокета
    timeOut.tv_usec = 0;
    setsockopt(rawSocket, SOL_SOCKET, SO_SNDTIMEO, &timeOut, sizeof(timeOut));  //устанавливаем таймаут
    setsockopt(rawSocket, SOL_SOCKET, SO_RCVTIMEO, &timeOut, sizeof(timeOut));  //3 секунды
    
    destAddr->sin_family = AF_INET;                                             //тип адреса - глобальный
    destAddr->sin_port = 0;                                                     //порт - не имеет значения
    
    
    //если ввели только адрес узла
    switch (argc)
    {
        case 2:
            
            //сырой сокет, прийдется запускать под рутом
            addrName = argv[1];
            printf(" *Введен адрес %s, continious ping по умолчанию, вывод в консоль\n", argv[1]);
            destAddr->sin_addr.s_addr = inet_addr(addrName);                            //получаем адрес в нужном формате
            return 1;
            break;
            //если ничего не ввели
        case 1:
            //сырой сокет, прийдется запускать под рутом
            addrName = "127.0.0.1";
            printf(" *Не введен адрес, localhost по умолчанию, continious ping по умолчанию, вывод в консоль\n");
            destAddr->sin_addr.s_addr = inet_addr(addrName);                            //получаем адрес в нужном формате
            return 2;
            break;
            
            //ввели IP и единичный пинг
        case 3:
            //сырой сокет, прийдется запускать под рутом
            addrName = argv[1];
            printf(" *Введен адрес %s, одиночный ping, вывод в консоль\n", argv[1]);
            destAddr->sin_addr.s_addr = inet_addr(addrName);                            //получаем адрес в нужном формате
            return 3;
            break;
            default:
            return 0;
    }
}

//ТЕЛО ПРОГРАММЫ
int main(int argc, const char * argv[]) {
    //декларации
    sockaddr_in destAddr;       //ip адрес узла
    int rawSocket;              //дескриптор сокета
    
    switch (mystart(&destAddr, argc, argv, rawSocket)) {
        case 1:
            continiousPing(rawSocket, &destAddr);
            break;
        case 2:
            continiousPing(rawSocket, &destAddr);
            break;
        case 3:
            onePing(rawSocket, &destAddr, 0);
            break;
        default:
            serveError();
            break;
    }
    myfinish();
    return 0;
}
