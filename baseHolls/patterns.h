/****************************************************************************
 * Шаблоны программы сбора и обработки информации. Версия для Symantec C
 * Copyright "SCADA-Pro" ltd. Moscow. Russia.
 ****************************************************************************/

//#define SIZE_TEST       // Проверка размера структур
#ifndef PATTERNS_H
#define  PATTERNS_H



#include "ztypes.h"
//#include <time.h>

//#include <dbcdef.h>
//#include <config.h>
//#include <uso.h>
//#include <slave.h>

#ifdef  __SC__
 #include <msgbuf.h>
#endif  /* __SC__ */

#ifndef  _QG
 //#define  _QG    near _pascal
 //#define  _CG    near _cdecl
#endif  /* _QG */

#define MAXCHREPER 15  /* максимальное число символов репера, включая '\0' */
#define MAXLENNAME 48  /* максимальное число символов названия параметра +1*/
#define MAX_PARAMCODE_LEN 33 /* число символов кода параметра + '\0'       */
#define NAMERECLEN      (MAXLENNAME + 2*MAX_PARAMCODE_LEN)
#define MAXUST      6  /* максимальное число технологических границ        */
#define MCHUST      5  /* максимальное число символов названия уставки +2  */
#define MNRAZM_44  32  /* max. dimensions types (ver 4.40)                 */
#define MNRAZM_45  64  /* max. dimensions types (ver 4.50)                 */
#define MAXNRAZM   MNRAZM_45  /* max. dimensions types                     */
#define MCHRAZM_44  8  /* max. dimension name characters + 2 (ver 4.40)    */
#define MCHRAZM_45 12  /* max. dimension name characters + 2 (ver 4.50)    */
#define MAXCHRAZM  MCHRAZM_45 /* max. dimension name characters + 1 ('\0') */
#define CODESCALELEN 4095. /* максимальный код датчика                     */
#define CODESCALEMSK 0xFFF /* 12 bit ADC mask                              */
#define MAXSCALENUM 100    /* максимальнальное число шкал датчиков         */
#define MAXMESSAGES 512 /*максимальное число сообщений в порту принтера    */
#define ENT_START_ROW 24 /* Первая строка адреса подключения в паспорте    */
#define ENT_DELTA_ROW 15 /* Высота ресурса для подключения                 */
#define SYS_FNT_NUM (conf.SystemFont) /* Системный фонт                    */
#define CURRENT_FONT  -1                /* текущий загруженный фонт */
#define CODESCALELEN16 65535. // for adc16 convert

enum PARAMETERS_TYPES {
        ALL_IN_BASE = -1,               /* All with reserve Все, вместе с резервными        */
        ANALOG,                         /* Analog Аналоговый                                */
        DISCR,                          /* Discrete 2 position Дискретный двухпозиционный   */
        ANALOG_EVAL,                    /* !atavism: Analog evaluate Аналоговый расчетный   */
        DISCR_EVAL,                     /* !atavism: Discrete evaluate Дискретный расчетный */
        DISCR_NPOS,                     /* Discrete many positions Дискретный многопозиционный    */
        PIPE,                           /* pipe Труборовод                                  */
        METER_LINE,                     /* meter line Измерительная линия                   */
    IMP_COUNTER,                    /* Impulse counter Счетчик импульсов дискретных     */
        SUPERFLOW,                      /* !atavism: Measuring thread SF !!! NO USED, ignored !!! */
        TIME_COUNTER,                   /* Time counter Счетчик времени                     */
    REM_ZOND,                       /* !atavism: Remote ZOND Удаленный ЗОНД             */
    EXTERNAL_TIMER,                 /* External timer Внешний таймер                    */
    DATE_TIME,                      /* Date_time Дата-Время                             */
    DISCR_8BIT,                     /* Discrete 8 bit Дискретный 8-ми битный            */
    EXTERN_COUNTER,                 /* External counter Внешний счетчик                 */
    LAST_SIGNED_TYPE,               /* Last signed type Последний определенный тип      */
        VOID_PARAM_TYPE=16,             /* Void type Произвольный тип                       */
    DISTURBED,                      /* Prohibition, sensor crash Запрет, неисправность датчика*/
    LAST_PARAM_TYPE
    };

    /* маски для типов параметров, номер бита соответствует */
    /* enum PARAMETERS_TYPES */
#define MASK_ALL_IN_BASE        0xFFFF  /* All with reserve Все, вместе с резервными     */
#define MASK_ANALOG             0x0001  /* AnalogАналоговый                   */
#define MASK_DISCR              0x0002  /* Discrete 2 position Дискретный двухпозиционный   */
#define MASK_ANALOG_EVAL        0x0004  /* Analog evaluate резерв                       */
#define MASK_DISCR_EVAL         0x0008  /* Discrete evaluate резерв                       */
#define MASK_DISCR_NPOS         0x0010  /* Discrete many positions Дискретный многопозиционный  */
#define MASK_PIPE               0x0020  /* pipe Труборовод                   */
#define MASK_METER_LINE         0x0040  /* meter line  Измерительная линия          */
#define MASK_IMP_COUNTER        0x0080  /* Impulse counter Счетчик импульсов дискретных */
#define MASK_SUPERFLOW          0x0100  /* Measuring thread SF резерв                       */
#define MASK_TIME_COUNTER       0x0200  /* Time counter Счетчик времени              */
#define MASK_REM_ZOND           0x0400  /* Remote ZOND Удаленный ЗОНД               */
#define MASK_EXTERNAL_TIMER     0x0800  /* External timer Внешний таймер               */
#define MASK_DATE_TIME          0x1000  /* Date_time Дата-Время                   */
#define MASK_DISCR_8BIT         0x2000  /* Discrete 8 bit Дискретный 8-ми битный       */
#define MASK_EXTERN_COUNTER     0x4000  /* External counter Внешний счетчик              */

#define mk_type_mask(type)      (1 << (type))

enum RETURN_CODES {
        NOT_FOUND       = -2,           /* Parameter not found    | Параметр не найден           */
        NULL_REPER,                     /* Reper pointer = NULL   | Указатель на репер = NULL    */
        OKEY,                           /* OK                     | Нормальное завершение        */
        INVALID_SYS_NUMBER,             /* Invalid system number  | Неверен системный номер      */
        ABSEND_PARAMETER,               /* No parameter           | Параметр отсутствует         */
        INVALID_TYP,                    /* Invalid paremeter type | Неверен тип параметра        */
        INVALID_VALUE                   /* Invalid value          | Неверное значение            */
        };

enum RestartCodes {
    RESTART_CODE_UNKNOWN,           /* Причина неизвестна   */
    RESTART_CODE_POWER_ON,          /* Включение питания    */
    RESTART_CODE_WATCHDOG,          /* Сработал WATCHDOG    */
    RESTART_CODE_RESET,             /* Нажата кнопка RESET  */
    RESTART_CODE_CORE,              /* Исключение           */
    RESTART_CODE_REMOTE_RESET       /* Удаленный перезапуск */
    };

#define TRUE  1
#define FALSE 0
#define ANY '\0'

#ifndef NULL
#define NULL 0
#endif

    /*--- Functions for working with components of BD Zond | Функции для работы с компонентами БД "Зонд" ------------*/
 enum T_ZE_NUMBERS           /* error codes                                 | коды ошибок                                */
  { ZE_ZERO = 0,             /* OK                                          | все хорошо!                                */
    ZE_CRTF = -1,            /* file/directory create error                 | ошибка при создании файла, директории      */
    ZE_OPENF = -2,           /* error file open                             | ошибка при открытии файла                  */
    ZE_FNF = -3,             /* file not found                              | файл не найден                             */
    ZE_BADVER = -4,          /* invalid version of file                     | неверная версия файла                      */
    ZE_BADFOR = -5,          /* invalid format of structure file error      | неверный формат, ошибка в структуре файла  */
    ZE_NOMEM = -6,           /* no memory for task                          | недостаточно памяти для выполнения         */
    ZE_RDE = -7,             /* error reading file                          | ошибка чтения файла                        */
    ZE_WRE = -8,             /* error writing file                          | ошибка записи                              */
    ZE_NOENT = -9,           /* 0 pointer of bad function argument          | 0-й указатель или ошибочный аргумент ф-ции */
    ZE_NLOAD = -10,          /* configuration file not load (not full) init | не загружен файл конфигурации (не полная)  */
                 /* initialization                              | инициализация                              */
    ZE_BADOPT = -11,         /* unknown option                              | неизвестная опция                          */
    ZE_NODFREE = -12,        /* no free memory in disk                      | недостаточно места на диске                */
    ZE_ACCES = -13,          /* no access to file (may be RDONLY)           | нет прав доступа к файлу (возможно RDONLY) */
    ZE_KERNELRES = -14,      /* no access kernel resources                  | не доступны ресурсы ядра                   */
    ZE_PK = -15,	     /* error packaging                             | не удалось упаковать                       */
    ZE_UNPK = -16,	     /* error unpackaging                           | не удалось распаковать                     */
    ZE_CRC = -17,            /* error file CRC                              | ошибка CRC файла                           */
                 /* ... reserve for file errors резерв для файловых ошибок */
                 /* Data base request errors                    | ошибки при обращении к параметрам БД */
    ZE_INVALID_SYS_NUMBER = -20,        /* invalid system number            | Неверен системный номер   */
    ZE_ABSEND_PARAMETER = -21,          /* absent parametr                  | Параметр отсутствует      */
    ZE_INVALID_TYP = -22,               /* invalid parametr type            | Неверен тип параметра     */
    ZE_INVALID_VALUE = -23,             /* invalid value                    | Неверное значение         */
    ZE_NOT_FOUND = -24,                 /* parametr not found               | Параметр не найден        */
    ZE_NULL_REPER = -25,                /* pointer to reper = null          | Указатель на репер = NULL */
    ZE_NSLOT = -26,                     /* no free slot in table            | В таблице нет свободного слота */
    ZE_EXIST = -27,                     /* element already exist            | В таблице уже есть такой элемент */
    ZE_BAD_USO = -28,                   /* invalid USO type                 | неверный тип УСО          */
    ZE_BAD_SLAVE = -29,                 /* invalid Slave type               | неверный тип Slave        */
    ZE_BOUND = -30,                     /* out of bounds                    | превышено допустимое значение */
    ZE_BAD_PARAMETER = -31,             /* invalid parametr value           | неверное значение параметра */
    ZE_CREAT_TRNODE = -32,              /* error tree node create           | при построении эл-та дерева ошибка */
    ZE_BAD_NUM = -33,                   /* invalid number of object         | неверный номер объекта (фрагмент,группа...) */
    ZE_BAD_NAME = -34,                  /* invalid name of object           | неверное имя объекта (фрагмент,группа...) */
    ZE_BAD_QUANT = -35,                 /* invalid number of objects        | неверное число эл-тов объекта */
    ZE_BAD_TIMESTAMP = -36,		/* time stamp is not the same       | не совпадает метка времени */
    ZE_NOT_IMPLEMENTED = -37,           /* function doesn't implemented     | ф-ция не поддерживается */
    ZE_BAD_ENTRY = -38,			/* error connecting                 | ошибочное подключение */
    ZE_EMPTY = -39,                     /* array or archive empty           | */

    ZE_TIME_SET_DISABLE = -40,          /* time set is disabled             | Установка времени запрещена в */
                    /* in program configuration         | конфигурации программы        */
    ZE_TIME_IN_SENSIT_BOUND = -41,      /* time in unsensitive zone         | Время в зоне нечувствительности */
    ZE_TIME_OUT_OF_RANGE = -42,         /* time is out of correction range  | Время за границами допустимых */
                    /* корректировок                 */
    ZE_BAD_NODE = -50,                  /* invalid adress of node           | неверный адрес узла */
    ZE_BAD_QRY  = -51,                  /* invalid query                    | неверный запрос */
    ZE_NO_CONNECT = -52,                /* not connection, procedure error  | нет соединения, ош-ка процедуры */
    ZE_EXCHG = -53,                     /* error while data exchanging      | ошибка при обмене данными */

    ZE_BUSY = -54,                      /* system busy */
    ZE_NOQRY = -55,                     /* no query (ask thread) */

    ZE_SEND = -56,                      /* send (packet) error */
    ZE_RECV = -57,                      /* receive (packet) error */

    ZE_THREADEXIT = -58,		/* thread received a command "exit (terminate)" */
                                        /* implode-explode (pack-unpack) ----*/
    ZE_BADDATA = -60,                   /* incorrect compressed data */
    ZE_BADINIT = -61,                   /* error in init phase */
    ZE_LOLEVERROR = -62,                /* low level error */
    ZE_TRANSPORT = -63,                 /* transport error */
    ZE_BADCMD = -64,                    /* bad command */

                                        /* Internal "ping" ------------------*/
    ZE_SOCK_ERROR = -80,                /* TCP/IP socket allocation error */
    ZE_SOCK_OPT_ERROR = -81,            /* TCP/IP setsockopt failed */
    ZE_BAD_HOST_NAME = -82,             /* Failed to resolve host name */
    ZE_BUF_SMALL = -83,                 /* TCP/IP receive buffer too small */
    ZE_PKT_BAD_SIZE = -84,              /* TCP/IP receive packet bad size */
    ZE_DEST_HOST_UNREACH = -85,         /* TCP/IP destination host unreachable */
    ZE_PKT_BAD_TYPE = -86,              /* TCP/IP bad packet type */
    ZE_BAD_PID = -87,                   /* ping from another local process */
    ZE_NO_PROTO = -88,                  /* WSAStartup init error, or hardware error */
    ZE_BAD_SEQ_NUM = -89,               /* Ping bad sequence number of packet */
    ZE_TIME_OUT = -90,                  /* receive time-out */

    ZE_MS_EXCEL = -93,                  /* ADB: MS Excel return error code */

    ZE_UNKNOWN = -100,                  /* unknown error неизвестная ошибка */
    ZE_UNKNOWN_ER_CODE = -101           /* unknown error code неизвестный код ошибки */
  };

#define ZE_OK   ZE_ZERO

#pragma pack (1)
/*--------------------- Executable file vertion Версия исполняемого файла ------------------------*/
struct ZOND_VERSION             /* Executable file vertion Версия выполняемого файла zondXYXX.exe */
 { BIT_FIELD  MainVersion :8;   /* High digit Старшая цифра версии */
   BIT_FIELD  MajorVersion:4;   /* Middle digitСредняя цифра версии */
   BIT_FIELD  MinorVersion:4;   /* Low digit Младшая цифра версии */
   short        BuildVersion;   /* Exe-file vertionВерсия EXE-файла     */
 };

/*------------------------- Конфигурация системы -------------------------*/
#define ZONDVIZA_ID_STR "ZONDVIZA4400"  /* идентификатор fL файла */
                    /* "zondviza.cfg" */
#define ZONDVIZA_QUANT  2               /* число записей в файле */

#define ZOND_VIZA_CONFIG_REC    1       /* номера записей */
#define USO_START_CONFIG_REC    2

 extern char g_sZondVizaCfgIdStr[];     /* ZONDVIZA_ID_STR */

#define ZONDVIZAVERSION_400     0x0004  /* версия 4.00 - 4.30 */
#define ZONDVIZAVERSION_440     0x0044  /* версия 4.40        */

    /* текущая версия стр-ры ZOND_VIZA_CONFIG хранится в conf.version */
#define ZONDVIZAVERSION ZONDVIZAVERSION_440

/*====================== Граничные константы ======================*/
#define MAXMESSAGE     20000    /* Макс. кол-во сообщений в ахриве */
#define MINMESSAGE         5    /* Мин. кол-во сообщений в ахриве */
#define DEFMESSAGE      1500    /* Кол-во сообщений по умолчанию */

#define MAXFRAGM        254     /* Макс. кол-во фрагментов */
#define MINFRAGM        -1      /* Нет основного фрагмента */

#define MAXPERIOD       60000   /* Макс. период обработки (в милисек.) */
#define MINPERIOD       100     /* Мин. период обработки */
#define DEFPERIOD       2000

#define MAXSAVE         60000   /* Макс. период сохранения ZOND.TMP в сек. */
#define MINSAVE         2       /* Мин. период сохранения */
#define DEFSAVE         (60*5)  /* Период по умолчанию */

#define MAXTUTIME       255     /* autocont stady wait time, sec */
#define MINTUTIME       1

#define MINKEEPMESDAY   1       /* messages, keep days */
#define MAXKEEPMESDAY   0x7FF
#define DEFKEEPMESDAY   90

#define MAXREMPERIOD    250     /* Для REMOTE */
#define MINREMPERIOD    0       /* Время пересылки данных, минуты */

#define MAXTIMEZONE     23      /* Для REMOTE */
#define MINTIMEZONE     -23     /* Разница во времени (+/-), часы */

#define MAXOFFTIME      240     /* (4 часа) Максимальное время вкл. screensaver-а */
#define MINOFFTIME      1       /* Минимальное время вкл. screensaver-а */

#define MAXWORKTIME     4       /* Максимальное число смен */
#define MINWORKTIME     1       /* Минимальное число смен */

#define MAXHOURINDAY    24      /* Максимальное глубина отчета */
#define MINHOURINDAY    1       /* Минимальная глубина отчета */

#define MINSTARTHOUR    -1

#define MINREPLPERIOD   6       /* Минимальный период запуска задачи */
                /* репликатора БД */
#define MAXREPLPERIOD   1530    /* Максимальный ---- (25,5 часов) */


struct ConfFlags
      { BIT_FIELD AdapterRegime : 3;    /* Режим монитора EGA/VGA/V60    */
    BIT_FIELD GraphTimeDir  : 1;    /* Направление оси времени       */
    BIT_FIELD PicFormat     : 3;    /* Формат "твердой" копии фрагмента*/
    BIT_FIELD light_pcnt    : 4;    /* Конечный уровень яркости в ед.по 10 % */
    BIT_FIELD tmp_pack      : 1;    /* 1 - упаковывать, 0 - нет ZOND.TMP */
    BIT_FIELD SetPermiss    : 1;    /* Разрешить занесение в базу извне */
    BIT_FIELD ConPermiss    : 1;    /* Разрешить управление извне */
    BIT_FIELD AutoChangeFr  : 1;    /* Автоматический переход на фрагмент с нарушением */
    BIT_FIELD SetTimePermiss: 1;    /* Разрешить коррекцию времени извне */
      };
struct ZondMainTasks                    /* Флаги запуска задач */
      { BIT_FIELD ShortMessageSrv : 1;  /* Short message server (SMS) */
    BIT_FIELD TFTPSrv	  : 1;	/* TFTP with Zond extensions */
    BIT_FIELD gz2dbf	  : 1;	/* start gz to dbf thread */
    BIT_FIELD rezerv1         : 13;
      };

struct ConfFlagsEx                      /* Флаги добавленные в ver 4.40 */
      { BIT_FIELD SaveMesDayDBF : 1;    /* write massages to dir "mes_day" in DBF file */
    BIT_FIELD RemoteReset   : 1;    /* Разрешение перезагрузки извне  */
    BIT_FIELD BasePrintMode : 1;    /* Not used | Режим распечатки паспортов */
                    /* 0 - полный 1 - краткий         */
    BIT_FIELD SirenType     : 2;    /* Тип сирены: 0 - стандартная    */
    BIT_FIELD MarkedMessage : 1;    /* Нужно ли слово "ВЫБРАН" при упр*/
    BIT_FIELD SeanseMessage : 1;    /* Нужно ли слово "СEАНС" при упр */
    BIT_FIELD SirenOff      : 1;    /* 1 - Полное запрещение звука    */
    BIT_FIELD add_LPT_narrow: 1;    /* 1 - Доп.принтер узкий (A4)	  */
    BIT_FIELD RemWriteDisable:1;	/* 1 - Запрещено выполнение       */
                    /*     команд write & del от удал.*/
                    /*     машины (remote host) 	  */
        BIT_FIELD SaveErrorList : 1;    /* write "syserr.log"             */
        BIT_FIELD SaveMesDayTXT : 1;    /* write massages to dir "mes_day" in TXT file */
        BIT_FIELD ReSoundDelay  : 3;    /* restore sound if no kvit delay */
        BIT_FIELD ArcMsgFmt45   : 1;    /* message.dbf format 0-4.40, 1-4.50 */
        BIT_FIELD ArcMsgFullName: 1;    /* use full name in v4.50 message */
        BIT_FIELD ArcMsgComment : 1;    /* unused: add kvit user comment  */
        BIT_FIELD NoRightMessage: 1;    /* put message to proto if no right to func access */
    BIT_FIELD reserv2       : 2;
    BIT_FIELD KeepMesDay    :11;    /* keep "mes_day" days             */
      };

#define CNT_RIGHT_GR_NUM 16
struct CntRights                        // for group or all zond
      {
        BIT_FIELD ContrRight     : 1;
        BIT_FIELD ContrRightTrust: 1;
        BIT_FIELD rezerv         : 14;
      };

struct DynamicFlags                     /* Флаги, инициализируемые не из файла */
      {
    BIT_FIELD BaseCRCFault  :1;    /* Состояние CRC паспортов: 0 - bad    */
    BIT_FIELD MesSaving     :1;    /* Ведение протокола: 0 - не вести     */
        BIT_FIELD dynSetPermiss    :1;    // conf.flags && conf.flagsEx dynamic
        BIT_FIELD dynConPermiss    :1;    // for AND denied control 06.2015
        BIT_FIELD reserv1       :4;
        struct CntRights	crznd;   // manual cnt rights for zond
        struct CntRights  crzgr[CNT_RIGHT_GR_NUM]; // manual cnt rights for groups
      };

//#define _F_AVG_TYPE     0x3     /* тип вывода (0-за N часов;1-по сменам;2-с часа) */
// #define AVG_TYPE(c)    ((c)->flags & _F_AVG_TYPE)
//  #define AVG_LAST_NHOUR_TYPE   0
//  #define AVG_SMENA_TYPE        1
//  #define AVG_FIXED_HOUR_TYPE   2
//  #define AVG_LAST_VALID_TYPE   AVG_FIXED_HOUR_TYPE
//#define _F_AVG_DELIM    0x4     /* тип символа-разделителя (0-после каждого часа;1-после перехода через смену) */
//#define _F_AVG_ARH      0x8     /* копировать ли отчеты в дир. AVERAGE    */
//#define _F_AVG_HOUR     0x10    /* формировать ли отчет среднечасовых значений */
//#define _F_AVG_SMEN     0x20    /* формировать ли отчет среднесменных значений */
//#define _F_AVG_DAYS     0x40    /* формировать ли отчет среднесуточных значений */
//#define _F_AVG_MONTH    0x80    /* формировать ли отчет среднемесячных значений */

struct AverHistoryConf
      { char kontr_hour;        /* контрактный час (0...23)              */
    char flags;             /* флаги                                 */
    char period;            /* число пред.смен/число часов           */
    char StartHour[4];      /* начала смен или -1 если смены нет     */
    char delimiter;         /* символ-разделитель между столбцами    */
    char decdelim;          /* разделитель десятичный ('.' или ',')  */
      };

struct hist_values
{
  double trust, untrust;
  int validity; // яЁшчэръ юЄёєЄёЄтш  фрээ√ї = -1
};
struct parameter_hist_values
{
  char* reper;                  //╚ь  ЁхяхЁр
  int sys_number;               //╤шёЄхьэ√щ эюьхЁ
  struct hist_values* values;   //╟эрўхэш
};

struct outputFormat
{
  BOOL printTrust;
  BOOL printUntrust;
  BOOL printAlltrust;
  BOOL printValidity;
  BOOL printMax;
  BOOL printMin;
  int  digits;           //╩юы-тю чэръют яюёых чря Єющ
};

struct parameter_hist_table
{
  char* header;                             // ╟руюыютюъ ЄрсышЎ√
  int value_save_type;                      // AVG_ Єшя√
  long int time_from;                       // ═рўрыю яЁюьхцєЄър эр ъюЄюЁюь чряЁр°штр■Єё  чэрўхэш
  long int time_to;                         // ╩юэхЎ яЁюьхцєЄър
  int      ParametersCount;                 // ╩юышўхёЄтю ярЁрьхЄЁют
  int      ValCount;                        // ╩юышўхёЄтю чэрўхэшщ
  struct parameter_hist_values* par_val;    // ╠рёёшт чэрўхэшщ (ярь Є№ т√фхышЄ№ чрЁрэхх)
  BOOL     isHorizontal;                    // ├юЁшчюэЄры№эр  °ърыр фрЄ
  BOOL     showFullInfoString;              // ╧юърч ёЄЁюъш ё яю ёэхэшхь фрээ√ї (яю фюёЄютхЁэ√ь/яю эхфюёЄютхЁэ√ь...)
  struct outputFormat *format;              // ╠рёёшт ЇюЁьрЄют т√тюфр ърцфюую чэрўхэш  (ярь Є№ т√фхышЄ№ чрЁрэхх)
};

#define MAX_SENSIT_BOUND        120     /* 2 минуты */
struct TimeSync
      { BIT_FIELD       use_tlimits :1; /* контролировать границы */
    BIT_FIELD       sensit_bound:7; /* граница зоны чуствительности +/- */
    BIT_FIELD       rezerv      :8;
    unsigned long   low_tlimit;     /* Время назад до... считать достоверным */
    unsigned long   high_tlimit;    /* Время вперед до... считать достоверным */
      };

struct _uso_share
{
  BIT_FIELD uso1:5;
  BIT_FIELD dir1:3;
  BIT_FIELD uso2:5;
  BIT_FIELD dir2:3;
};

#define USO_SEM_SHARE 4
// change this mask if new implementations will created - Nik!
#define SEM_SHARED_USO_MASK ((1<<MODBUS_M)|(1<<MAGISTRAL_1)|(1<<IMPULS)|(1<<IMPULS_SF))

struct _abd_conf
{                                     // see also ZondMainTasks gz2dbf
  BIT_FIELD delfile_day         :8;   // days old to clear gz files
  BIT_FIELD write_term_to_file  :1;   // put adb task termilal report to file
  BIT_FIELD continue_term_file  :1;   // append this file on start
  BIT_FIELD user_dbf_templ      :1;   // 0 - zond default distrib templates, 1 - user (in base\dbftempl)
  BIT_FIELD vendor_num          :2;   // 0 - 1 vendor,... max 4, so hmi present as n+1
  BIT_FIELD ext_root            :1;
  BIT_FIELD forceP              :1;
  BIT_FIELD forceDP             :1;
  BIT_FIELD fPrazm              :2;   // kg/sm2,bar, MPa, KPa
  BIT_FIELD fDPrazm             :2;   // kg/m2, bar, MPa, KPa
  BIT_FIELD rez1                :12;
};                                    // size = 2 bytes

#define ZVPATHSIZE   30
#define ZONDNAMESIZE 32                 /* длина имени комплекса "Зонд"   */
struct ZOND_VIZA_CONFIG {
        short version;                  /* Версия системы                 */
    unsigned short maxcodes;        /* Количество параметров в БД     */
    char  path_to_database[ZVPATHSIZE];   /* Путь к базе данных             */
        char  rezerv2[2];
    unsigned short saving_period;   /* Период записи БД на диск       */
    short outputdevice;             /* Устройство вывода сообщений    */
    char  system_LPT;               /* Принтер для печати системных   */
                    /* сообщений */
    char  additional_LPT;           /* Принтер для печати рапортов,   */
                    /* фрагментов, текстов */
        unsigned short max_message_num; /* Размер архивного файла         */
        long  Sbor_time_cycle;          /* Период обработки параметров    */
        short main_fragm;               /* Номер основного фрагмента      */
    struct ConfFlags flags;         /* Флаги см. выше                 */
    char  RZ_rezerv[8];             /* Резерв от REM_ZOND             */
    char  path_to_images[64];       /* Путь к "твердой" копии фрагмента */
    unsigned char screen_off_time;  /* Время до гашения экрана в мин  */
    struct AverHistoryConf ahc;     /* Конфигурация задачи усреднения */
    char  ZondName[ZONDNAMESIZE];   /* Имя Зонда (сетевое)            */
    struct ZondMainTasks task;      /* Признаки запуска задач         */
    char  main_fragm_PG;            /* main fragment is Pseudo Graphic*/
    char  SystemFont;               /* Номер ресурса с системным фонтом */
                    /* -1; resnum = SystemFont+1      */
    struct ConfFlagsEx flagsEx;     /* Флаги см. выше                 */
    char  rezerv4[50];              /* removed NWserv: сервер NetWare */
    struct TimeSync    TSync;       /* границы корректировки времени  */
    unsigned char SMsRunDelay;	/* sort message start delay       */
        char uso_sem_share_mask;        /* 0x0F                           */
    struct _uso_share uss[USO_SEM_SHARE];
        struct _abd_conf adb;
        unsigned int codes_right_margin;/* DB last sys# + 1. default == maxcodes */
    char   rezerv3[4];
    };                              /* size of struct 256 byte */

enum ADAPTER_REGIME { EGA_REGIME, VGA_REGIME, V60_REGIME };
/*------------------ Флаги в паспортах параметров ------------------------*/
//#define _F_MAIN_LIST    0x01
//#define _F_KVIT_GOOD    0x02
//#define _F_MES_WINDOW   0x04
//#define _F_PRN          0x08
//#define _F_ARC_FILE     0x10
//#define _F_SGL          0x20    /* для аналоговых */
//#define _F_INVERS       0x20    /* для дискретных */
//#define _F_INTEGRAL     0x40    /* для аналоговых */
//#define _F_CHANGE_BITS  0x40    /* для дискретных */
//#define _F_KVIT_BAD     0x80
//#define _F_CNT_TYPE     0x100   /* для дискретных */

struct ParamFlags {
    BIT_FIELD F_MAIN_LIST  : 1; /* признак основного списка               */
    BIT_FIELD F_KVIT_GOOD  : 1; /* требуется квитирование улучшения       */
    BIT_FIELD F_MES_WINDOW : 1; /* вывод в окно сообщений                 */
    BIT_FIELD F_PRN        : 1; /* вывод на принтер                       */
    BIT_FIELD F_ARC_FILE   : 1; /* вывод в файл                           */
    BIT_FIELD F_SGL        : 1; /* признак сглаживания/инверсия/направл.  */
    BIT_FIELD F_INTEGRAL   : 1; /* признак интегрирования/обмена/цикл.    */
    BIT_FIELD F_KVIT_BAD   : 1; /* требуется ли квитирование ухудшения    */
    BIT_FIELD F_CNT_TYPE   : 1; /* for DISCR 0 - crane, 1 - no crane      */
    BIT_FIELD F_DISAB_TC0  : 1; // 03.08 disable TC cmd in HMI tc tools
    BIT_FIELD F_DISAB_TC1  : 1; // one bit per state, set in pasp as chk box
    BIT_FIELD F_DISAB_TC2  : 1;
    BIT_FIELD F_DISAB_TC3  : 1;
    BIT_FIELD F_KVIT_NOTRUST : 1; // 06.10 kvit pass to no trust
    BIT_FIELD F_rezerv     : 2;
  };
#define F_INVERS        F_SGL      /* признак инверсии для дискретных      */
#define F_CHANGE_BITS   F_INTEGRAL /* обмена битов для 4-х поз. дискретных */
#define F_TIMECNTDIRECT F_SGL      /* forward-backward | прямой-обратный счетчик времени      */
#define F_TIMECNTCYCLE  F_INTEGRAL /* accumulate-cyclic| накопительный-циклический сч.времени */
#define F_IMP_CNTDIRECT F_SGL      /* forward-backward | прямой-обратный счетчик импульсов    */
#define F_IMP_CNTCYCLE  F_INTEGRAL /* accumulate-cyclic| накопительный-циклический сч.импульс */

enum UST_NUMBERS // ANALOG,ANALOG_EVAL,SUPERFLOW  │TIME_COUNTER,IMP_COUNTER & EXTERNAL_TIMER
 { UST_NVG,     /* ust[0] нижняя возможная граница│┐Граница счета                          */
   UST_NAG,     /* ust[1] нижняя аварийная граница│┘(только TIME_COUNTER и IMP_COUNTER)    */
   UST_NTG,     /* ust[2] нижняя техн-ская граница                                         */
   UST_DELTA,   /* ust[3] delta ТГ относительно текущего значения                          */
   UST_VTG,     /* ust[4] верхняя технологическая граница                                  */
   UST_VAG,     /* ust[5] верхняя аварийная граница ┐Время (кол-во импульсов) срабатывания */
   UST_VVG,     /* ust[6] верхняя возможная граница ┘сигнала(-1 не задано)                 */
   UST_DELTA2,  /* Delta2 delta АГ относительно текущего значения                          */
   UST_SENS     /* an_pasp.sensitiveness                                                   */
 };

/*-------------- Analog parameter pasport | Паспорт аналогового параметра ------------------*/
#define MIN_SCALEB    (-32768)
#define MAX_SCALEB    32767
#define MIN_SCALE     1
#define MAX_SCALE     0xFFFF
#define MIN_POR       -7
#define MAX_POR       7

struct an_pasport {                  /* pasport pattern | шаблон паспорта                   */
    char     reper [MAXCHREPER];     /* parameter reper | репер параметра                   */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    short ust [MAXUST+1];            /* технологические уставки           */

    short scaleb;                    /* begin of scale | начало шкалы                       */
    char  POR;                       /* scale exponent (porjadok) |  порядок шкалы          */
    char  RAZM;                      /* code of dimension | код размерности                 */
    unsigned char sensitiveness;     /* sensitive | чувствительность                        */
    unsigned char nscale;            /* scale number if | номеp шкалы пpи n_grad != 0       */
    unsigned short scale;            /* sensor scale | шкала датчика                        */
    unsigned short ksg[3];           /* константы сглаживания             */
    unsigned char sbros_time;        /* Время начала интегрирования       */
    unsigned char n_grad;            /* номеp гpадуиpовки                 */
    unsigned char day;               /* дата последней тарировки          */
    unsigned char month;             /*                          датчика  */
    short         Delta2;            /* Дельта для изменения НАГ и ВАГ    */
    unsigned char c_table;           /* color table #                     */
    unsigned char rezerv1[3];
#ifdef __SC__
    unsigned cd_ident   :24;         /* идентификатор уст-ва управления   */
    unsigned timeout    :8;          /* timeout during control            */
#else                                /* MSC 5.1 не понимает : 24*/
    unsigned char cd_ident[3];       /* идентификатор уст-ва управления   */
    unsigned char timeout;           /* timeout during control            */
#endif
  };
/*------------------ Паспорт дискретного параметра -----------------------*/
struct dis_pasport {
    char  reper [MAXCHREPER];        /* репер параметра                   */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    unsigned char c_table;           /* номер таблицы цветов              */
    unsigned char norma;             /* ноpмальное состояние              */
    char condition [4][9];           /* тексты состояний                  */
#ifdef __SC__
    unsigned cd_ident   :24;         /* идентификатор уст-ва управления   */
    unsigned timeout    :8;          /* timeout during control, sec       */
#else                                /* MSC 5.1 не понимает : 24*/
    unsigned char cd_ident[3];       /* идентификатор уст-ва управления   */
    unsigned char timeout;           /* timeout during control, sec       */
#endif
};
/*--------- Паспорт восьмипозиционного дискретного параметра -------------*/
struct npos_pasport {
    char  reper [MAXCHREPER];        /* репер параметра                   */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    unsigned char c_table;           /* номер таблицы цветов              */
    unsigned char norma;             /* ноpмальное состояние              */
    char condition [8][4];           /* тексты состояний                  */
    BIT_FIELD F_DISAB_TC4  : 1;     // disable TC cmd in HMI tc tools
    BIT_FIELD F_DISAB_TC5  : 1;     // one bit per state, set in pasp as chk box
    BIT_FIELD F_DISAB_TC6  : 1;     // additinal to flags field
    BIT_FIELD F_DISAB_TC7  : 1;
    BIT_FIELD rezerv2      : 12;
    unsigned char rezerv1[6];
};
/*--------- Паспорт восьмибитного дискретного параметра ------------------*/
struct discr_8bit {
    char  reper [MAXCHREPER];        /* репер параметра                   */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    unsigned char c_table;           /* номер таблицы цветов              */
    unsigned char norma;             /* ноpмальное состояние              */
    char condition [8][5];           /* тексты-идентификаторы битов       */
};
/*----------- Паспорт измерительной линии по данным телемеханики ---------*/
struct meter_line {                  /* шаблон паспорта                   */
    char     reper [MAXCHREPER];     /* репер параметра                   */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    short    sysQ_Nk;
    short    sysP_Nn;
    short    sysT;
    short    sysPipe;
    short    dPn_max;
    unsigned char c_table;           /* номер таблицы цветов              */
    char     r0;
    short    r1;
    short    scaleb;                 /* begin of scale | начало шкалы                       */
    char     POR;                    /* scale exponent (porjadok) |  порядок шкалы          */
    char     RAZM;                   /* code of dimension | код размерности                 */
    char     l;                      /* Угловой / фланцевый               */
    unsigned char rezerv2;
    unsigned short scale;            /* sensor scale | шкала датчика      */
    float    D20_d20[2];
    float    L_L;
    short    r2[4];
  };
/*------------------ Паспорт трубопровода --------------------------------*/
struct meter_pipe {                  /* шаблон паспорта                   */
    char     reper [MAXCHREPER];     /* репер параметра                   */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
                     /* Следующие значения используются   */
                     /* при флаге статуса valtype равном  */
                     /* TYPE_MANUAL                       */
    float    N2_CO2[2];              /* концентрация N2 и CO2             */
    float    Beta_Beta_[2];
    short    Ron_Pb[2];              /* Плот. и бар., умноженные на 10000 */
    short    sbros_time;             /* Время начала интегрирования       */
    long     CorrectTime;            /* Время ввода состава газа          */
                     /* Ссылки на параметры используются  */
                     /* при флаге статуса valtype равном  */
                     /* TYPE_LOCAL                        */
#define METER_PIPE_SYS_N2      0
#define METER_PIPE_SYS_C02     1
#define METER_PIPE_SYS_Ro      2
#define METER_PIPE_SYS_Pb      3     /* see below                         */
    unsigned short sys[4];           /* Сист. # N2, CO2, Ro, Pb           */
    unsigned char  c_table;          /* номер таблицы цветов              */
    char     r0;
    short    r1[3];
  };
/*--------------------------------------------------------------------------*/
struct impcount_pasport {            /* Счетчик импульсов дискретных */
    char     reper [MAXCHREPER];     /* репер параметра              */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    long     StartValue;             /* начальное значение                */
    unsigned char c_table;           /* color table #                     */
    char     rezerv1[5];
    long     SignalBoundary;         /* значение срабатывания сигнала     */
    short    rezerv2[14];
  };
/*--------------------------------------------------------------------------*/
struct timecount_pasport {           /* Счетчик времени              */
    char     reper [MAXCHREPER];     /* репер параметра              */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    unsigned long CountBoundary;     /* Граница (период) счета            */
    unsigned char c_table;           /* color table #                     */
    char     rezerv1[5];
    unsigned long SignalBoundary;    /* Время срабатывания сигнала        */
    short    rezerv2[14];
  };
/*--------------------------------------------------------------------------*/
struct exttimer_pasport {            /* Внешний таймер               */
    char     reper [MAXCHREPER];     /* репер параметра              */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    unsigned char c_table;           /* color table #                     */
    char     rezerv1[9];
    long     SignalBoundary;         /* Время срабатывания сигнала        */
    short    rezerv2[14];
  };
/*--------------------------------------------------------------------------*/
struct datetime_pasport {            /* Дата-Время                   */
    char     reper [MAXCHREPER];     /* репер параметра              */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    unsigned char c_table;           /* color table #                     */
    char     rezerv0;
    short    rezerv1[20];
  };
/*--------------------------------------------------------------------------*/
struct extcount_pasport {            /* Внешний счетчик              */
    char     reper [MAXCHREPER];     /* репер параметра              */
    _BYTE    rez;                    /* not used                          */
    struct   ParamFlags flags;       /* флаги                             */
    _WORD    LocalCheckSum;          /* контрольные суммы НСИ параметра в */
    _WORD    ExternCheckSum;         /* своей и "нижней" базах данных     */
    unsigned char c_table;           /* color table #                     */
    char     rezerv1[9];
    long     SignalBoundary;         /* значение срабатывания сигнала     */
    short    rezerv2[14];
  };
/*--------------------------------------------------------------------------*/
union  PASPORT
 { char     reper [MAXCHREPER];         /* репер параметра              */
   struct an_pasport        Analog;     /* Аналоговый                   */
   struct dis_pasport       Discr;      /* Дискретный двухпозиционный   */
                    /* Аналоговый расчетный         */
                    /* Дискретный расчетный         */
   struct npos_pasport      Npos;       /* Дискретный многопозиционный  */
   struct meter_pipe        Pipe;       /* Труборовод                   */
   struct meter_line        mLine;      /* Измерительная линия          */
   struct impcount_pasport  Icount;     /* Счетчик импульсов дискретных */
                    /* Измерительная нитка SF       */
   struct timecount_pasport Tcount;     /* Счетчик времени              */
                    /* Удаленный ЗОНД               */
   struct exttimer_pasport  ExtTimer;   /* Внешний таймер               */
   struct datetime_pasport  DateTime;   /* Дата-Время                   */
   struct discr_8bit        Bit8;       /* Дискретный 8-ми битный       */
   struct extcount_pasport  ExtCount;   /* Внешний счетчик              */
 };
/*--------------------------------------------------------------------------*/
#pragma pack (4)

/*------------ Индексы значений в расширенной базе + дополнения ------------*/
#define EXT_VAL_FALSE   0     /* Расход с начала суток недостоверно         */
#define EXT_VAL_TRUE    1     /* Расход с начала суток достоверно           */
#define EXT_VAL_PREVDAY 2     /* Double, содержащий расход за прошлые сутки */
#define EXT_VAL_MOUNTH  3     /* Double, содержащий расход с начала месяца  */
#define EXT_VAL_SYSNUM  4     /* Для совместимости с интерпретатором формул */
#define EXT_VAL_TOTAL   5     /* Расход с начала суток всего                */
enum EXT_UST
      { EXT_VAL_UST_NVG=EXT_VAL_TOTAL+1,                /* Значения уставок */
    EXT_VAL_UST_NAG,
    EXT_VAL_UST_NTG,
    EXT_VAL_UST_DELTA,
    EXT_VAL_UST_VTG,
    EXT_VAL_UST_VAG,
    EXT_VAL_UST_VVG,
    EXT_VAL_NNG,                    /* Номер нарушенной границы */
    EXT_VAL_SCALEB,                 /* Начало шкалы */
    EXT_VAL_SCALE                   /* Длина шкалы */
      };
    /* Для счетчиков времени и импульсов */
#define EXT_VAL_COUNTER_PREV_ZERO_TC EXT_VAL_PREVDAY /* Предыдущее значение обнуляющего параметра */
#define EXT_VAL_COUNTER_PREV_WORK_TC EXT_VAL_MOUNTH  /* Предыдущее значение ТСгенератора импульсов*/
/*=========================================================================
                        Расширенная БД

     double[0]     │     double[1]     │      double[2]    │     double3]
  ───────┬─────────┼─────────┬─────────┼─────────┬─────────┼─────────┬─────
 float[0]│ float[1]│ float[2]│ float[3]│ float[4]│ float[5]│ float[6]│float[7]

  ------------------- Аналоговый и аналоговый расчетный --------------

 текущее значение  │ с нач. суток всего│за прошлые сутки   │ с начала месяца

  ------------------------- Счетчики времени и импульсов -------------
           │                   │предыдущее значен. │предыдущее значен.
           │                   │обнуляющего п-тра  │ТСгенератора импульсов

  ---------- Измерительная линия по данным телемеханики --------------

 с нач.суток недост│с нач.суток достов.│за прошлые сутки   │ с начала месяца

 *========================================================================*/

struct mag_code {         /* шаблон шифров "Магистраль" и SUPERFLOW*/
   unsigned kp       : 6; /* номер КП                   номер SF   */
   unsigned enter    : 4; /* номер входа (первый бит)   номер нитки*/
   unsigned type     : 4;
   unsigned rez3     : 2;
   unsigned ato      : 7; /* АТО      (первый бит)      индекс     */
   unsigned dir      : 3; /* номер направления                     */
   unsigned rez2     : 6;
   unsigned ato_TU   : 8; /* АТО управления                        */
   unsigned rez5     : 8; /* ato_TI - not used. АТО дополнит. телеизмерения при ТУ */
   unsigned rez4     : 9;
   unsigned bit2     : 1; /* число битов 0 - 1, 1 - 2  ! FIXED  !  */
   unsigned uso_type : 5; /* тип УСО                   ! FIXED  !  */
   unsigned rezerv   : 1; /* "дырка"                   ! FIXED  !  */
   };

struct orcode {                       /* шаблон шифров Орион       */
   unsigned orion    : 2;             /* N ОРИОНа                  */
   unsigned rez2     : 8;
   unsigned type     : 4;             /* тип: == 1 -> давление     */
   unsigned rez3     : 2;
   unsigned plate    : 8;             /* N агрегата (платы)        */
   unsigned param    : 8;             /* N параметра (первый бит)  */
   unsigned rez4     :16;
   unsigned rez5     : 9;
   unsigned bit2     : 1;             /* число битов 0 - 1, 1 - 2  */
   unsigned uso_type : 5;             /* тип УСО                   */
   unsigned rezerv   : 1;             /* "дырка"                   */
   };

struct sf_code { /* code pattern  шаблон шифров SUPERFLOW  Гиперфлоу     GVC-2010     Sevc-D,Merc     IRTM       EuroAlpha  VKG-2   SPG */
   unsigned sf       : 6; /* number SDF    номер SF        БИЗ           N контр.     N dev           # dev      #dev       #vkg    #dev */
   unsigned run      : 4; /* number thread номер нитки     ГФ                                         # channel  -          #vkg    номер нитки */
   unsigned type     : 4; /*                 Модель ГФ                                  -          -                  модель СПГ */
   unsigned rez3     : 2;
   unsigned param    : 7; /* parameter number номер пар-ра    номер пар-ра  N пар-ра мл. N param, lo.    value type value type #param  номер пар-ра */
   unsigned dir      : 3; /* direction num    номер напр.     номер напр.   N напр.      N dir(dev)      #dir       #dir       #dir    номер напр. */
   unsigned func     : 6; /*                               N пар-ра ст. N param, hi     -          -          -       тип пар-ра */
   unsigned rez6     : 8;
   unsigned rez4     : 8;
   unsigned rez5     : 9;
   unsigned bit2     : 1; /* число битов 0 - 1, 1 - 2              */
   unsigned uso_type : 5; /* тип УСО (0 - Ц, 1 - М)                */
   unsigned rezerv   : 1; /* "дырка"                               */
   };

struct elec_code {       /* code pattern for electricity counters CE27*/
  unsigned dev      : 6; /* number SDF    #dev */
  unsigned run      : 4; /* number thread #dir */
  unsigned type     : 4; /*                    */
  unsigned rez3     : 2;
  unsigned param    : 7; /* parameter number*/
  unsigned dir      : 3; /* direction num      */
  unsigned func     : 6; /*                    */
  unsigned tariff   : 4; /* tariff number      */
  unsigned rez4     : 12;
  unsigned rez5     : 9;
  unsigned bit2     : 1; /* число битов 0 - 1, 1 - 2              */
  unsigned uso_type : 5; /* тип УСО (0 - Ц, 1 - М)                */
  unsigned rezerv   : 1; /* "дырка"                               */
};

struct rem_zond_code {
   unsigned rez3     :10;
   unsigned type     : 4;       /* тип в исх.БД                    */
   unsigned rez4     : 2;
   unsigned zond     : 5;       /* номер ЗОНДА                     */
   unsigned rez2     :11;
   unsigned param    :20;       /* sys# 0...1048575 | системный номер в исх.БД */
   unsigned rez5     : 2;
   unsigned copy_stat: 1;	/* 1-копировать статус,0-нет,syslink==1  */
   unsigned copy_ust : 1;       /* 1-копировать уставки,0-нет,syslink==1 */
   unsigned syslink  : 1;       /* 0/1 Стат./дин. sys(param)       */
   unsigned bit2     : 1;       /* число битов 0 - 1, 1 - 2        */
   unsigned uso_type : 5;       /* тип: УСО REM_ZOND               */
   unsigned rezerv   : 1;       /* "дырка"                         */
   };

enum FILE_USO_CODE_ID_STR
 { FILE_USO_IDSTR_NOTUSED,	/* not used  | строковый идентификатор не используется */
   FILE_USO_IDSTR_REPER,	/* reper     | строковый идентификатор - репер */
   FILE_USO_IDSTR_CODE1,	/* code1     | -*- код1 */
   FILE_USO_IDSTR_CODE2,        /* code2     | -*- код2 */
   FILE_USO_IDSTR_NAME,         /* fill name | -*- полное наименование */
   FILE_USO_IDSTR_DIRECT        /* direct id | -*- указан в подкючении */
 };

enum FILE_USO_A2X
 { FILE_USO_ATOI, 		/* signed integer */
   FILE_USO_ATOU,               /* unsigned integer */
   FILE_USO_ATOO,               /* octal integer */
   FILE_USO_ATOX,               /* hex integer */
   FILE_USO_ATOD                /* float point double precision */
 };

struct file_uso_code {
   unsigned file_no  : 8;	/* #файла 0...FDAT_MAX_FILE        */
   unsigned id_str   : 3;	/* где хранится идентификатор 	   */
                /* (см.enum FILE_USO_CODE_ID_STR)  */
   unsigned rez00    : 5;	/* способ преобразования           */

   unsigned atoX     : 6;	/* способ преобразования           */
                /* (см. enum FILE_USO_A2X)         */
   unsigned rez01    : 10;
   unsigned rez03    : 16;
   unsigned rez04    : 9;
   unsigned bit2     : 1;       /* число битов 0 - 1, 1 - 2 !FIXED */
   unsigned uso_type : 5;       /* type: USO_FILE           !FIXED */
   unsigned rezerv   : 1;       /* "дырка",hole             !FIXED */
   };

#define COUNTER_RESET_01        0     /* Clear if "sys_zero" 0->1 */
#define COUNTER_RESET_10        1     /* Clear if "sys_zero" 1->0 */
#define COUNTER_RESET_01_10     2     /* Clear if "sys_zero" 0->1 | 1->0 */

struct time_count_codes {
   unsigned rez3     :14;
   unsigned zero_cond: 2;             /* Clear condition | условие для обнуления счетчика        */
   unsigned sys_zero :16;             /* sys# clear param| системный номер обнуляющего параметра */
   unsigned sys_work :16;             /* sys# count param| системный номер параметра счета       */
   unsigned work_cond: 3;             /* Count condition | условие для счета времени или ипульсов*/
   unsigned rez5     : 6;
   unsigned bit2     : 1;
   unsigned uso_type : 5;
   unsigned rezerv   : 1;             /* "дырка"                   */
   };
typedef struct time_count_codes imp_count_codes;

struct ccc_code {                     /* шаблон шифров MODBUS_M    */
   unsigned cnt_addr : 12; /* адрес Coila/Holdinga в упр/рег        */
   unsigned kp2      : 2; /* hi bits of kp   */
   unsigned mbtype   : 2; /* (Coil/Disc/Inp/Hold)                  */
   unsigned addr     : 12;/* номер mb-сигнала                      */
   unsigned dir      : 4; /* номер линии MODBUS_M (0..15)           */
   unsigned trs_addr : 12;/* номер mb-сигнала достоверности        */
   unsigned trs_type : 2; /* способ получения достоверности        */
   unsigned trs_mbtyp: 2; /* (Coil/Disc/Inp/Hold) достоверности    */
   unsigned norma    : 2; // 0,1,равенство - при достоверности и управлении
   unsigned kp1      : 6; /* номер КП - номер контроллера          */
   unsigned adcform  : 1; /* нужно ли привести к формату АЦП       */
   unsigned bit2     : 1; /* число битов 0 - 1, 1 - 2  ! FIXED  !  */
   unsigned uso_type : 5; /* тип УСО                   ! FIXED  !  */
   unsigned rezerv   : 1; /* "дырка"                   ! FIXED  !  */
};

#define make_kp(kp1,kp2) (((_DWORD)(kp2)<<6) | (_DWORD)kp1)
#define put_kp(kp1,kp2,kp) kp1 = kp & 0x003f; kp2 = kp >> 6

struct mbl_code {                     /* шаблон шифров MODBUS_L    */
   unsigned kp       : 8; /* номер контроллера MODBUS_L (0..253)   */
   unsigned trs_type : 2; /* способ получения достоверности        */
   unsigned rez15    : 5;
   unsigned stype    : 1; /* (Coil/Hold)                           */
   unsigned dir      : 3; /* номер линии MODBUS_L (0..7)           */
   unsigned rez2     : 1;
   unsigned addr     : 12;/* номер mb-сигнала                      */
   unsigned trs_addr : 12;/* номер mb-сигнала ссылки               */
   unsigned rez13    : 2;
   unsigned trs_styp : 1; /* Coil/Hold ссылки                      */
   unsigned rez      : 1;
   unsigned norma    : 2; /* нормальное/достоверное значение       */
   unsigned rez6     : 6;
   unsigned adcform  : 1; /* нужно ли привести к формату АЦП       */
   unsigned bit2     : 1; /* число битов 0 - 1, 1 - 2  ! FIXED  !  */
   unsigned uso_type : 5; /* тип УСО                   ! FIXED  !  */
   unsigned rezerv   : 1; /* "дырка"                   ! FIXED  !  */
   };

struct eval_code {                    /* шаблон шифров вычислителя */
   unsigned rez5     : 8;
   unsigned rez3     : 2;
   unsigned type     : 4;
   unsigned rez4     : 2;
   unsigned number   : 16;            /* номер переменной EVAL */
   unsigned rez2     : 8;
   unsigned enter    : 4;             /* номер задачи (алгоблока) */
   unsigned rez6     : 12;
   unsigned rez7     : 1;
   unsigned bit2     : 1;             /* число битов 0 - 1, 1 - 2  */
   unsigned uso_type : 5;             /* тип УСО                   */
   unsigned rezerv   : 1;             /* "дырка"                   */
   };

struct emi_code {                     /* шаблон шифров ЭМИКОНА     */
   unsigned kp       : 4;  // номер контроллера
   unsigned rez2     : 2;
   unsigned subadr   : 4;  // номер платы  DI
   unsigned rez5     : 6;
   unsigned c_param  : 6;  // номер сигнала на плате DO
   unsigned rez3     : 1;
   unsigned dir      : 2;  // номер линии Эмиконов
   unsigned rez7     : 3;
   unsigned c_subadr : 4;  // номер платы  DO
   unsigned param    : 6;  // номер сигнала на плате DI
   unsigned rez4     : 10;
   unsigned rez6     : 9;
   unsigned bit2     : 1;  // число битов 0 - 1, 1 - 2  ! FIXED  !
   unsigned uso_type : 5;  // тип УСО                   ! FIXED  !
   unsigned rezerv   : 1;  // "дырка"                   ! FIXED  !
   };

struct mark_code {
   unsigned rez2     : 8;
   unsigned rez3     : 2;
   unsigned rez4     : 6;
   unsigned number   :16;             /* номер переменной          */
   unsigned delimitr :16;             /* делитель для аналоговых   */
   unsigned arr_num  : 8;             /* номер массива             */
   unsigned rez5     : 1;
   unsigned bit2     : 1;             /* число битов 0 - 1, 1 - 2  */
   unsigned uso_type : 5;             /* тип УСО                   */
   unsigned rezerv   : 1;             /* "дырка"                   */
   };

struct diag_code {                /* шаблон подключения Диагностики     */
   unsigned kp       : 8;  // номер контроллера, controller number
   unsigned reserv1  : 2;
   unsigned type     : 4;  // 0-zond,1-USO,2-slave,system,speed ! FIXED !
   unsigned reserv2  : 2;
   unsigned param    :10;  // parameter type
   unsigned object   : 6;  // N USO or slave
   unsigned signal   :16;
   unsigned dir      : 8;
   unsigned rez6     : 1;
   unsigned bit2     : 1;  // bit number  0 - 1, 1 - 2  ! FIXED  !
   unsigned uso_type : 5;  // USO type                  ! FIXED  !
   unsigned rezerv   : 1;  // 1-hole/0-used             ! FIXED  !
   };

struct diag_code_IP4ping { // USO diag - IP ping
   unsigned lo_ip_8  : 8;  // low part destination IP address
   unsigned reserv1  : 2;
   unsigned type     : 4;  // 0-zond,1-USO,2-slave,system,speed ! FIXED !
   unsigned reserv2  : 2;
   unsigned param    :10;  // parameter type
   unsigned object   : 6;  // not use
   unsigned hi_ip_24 : 24; // ho part destination IP address
   unsigned rez6     : 1;
   unsigned bit2     : 1;  // bit number  0 - 1, 1 - 2  ! FIXED  !
   unsigned uso_type : 5;  // USO type                  ! FIXED  !
   unsigned rezerv   : 1;  // 1-hole/0-used             ! FIXED  !
   };
#define getCodeIP4pingIP(p)     (((p)->hi_ip_24 << 8) + ((p)->lo_ip_8))
#define setCodeIP4pingIP(p,ip)  { (p)->hi_ip_24 = (unsigned int)(ip) >> 8; (p)->lo_ip_8 = (ip) & 0xFF; }

struct opcm_code {                /* шаблон подключения opcm client    */
   unsigned client   : 4;   // номер контроллера
   unsigned offs_set : 1;   // if 1 - offset hold correct value
   unsigned cnt      : 1;   // controlled/reguled
   unsigned rezerv1  : 10;
   unsigned offs     : 16;  // offset in client class list while task worked
   unsigned reserv3  : 16;
   unsigned reserv4  : 9;
   unsigned bit2     : 1;  // bit number  0 - 1, 1 - 2  ! FIXED  !
   unsigned uso_type : 5;  // USO type                  ! FIXED  !
   unsigned rezerv   : 1;  // "дырка"                   ! FIXED  !
   };

struct db_64 {
   unsigned long lo;
   unsigned long hi;
};
struct db_64s {
   long lo;
   long hi;
};

union CODE {
   struct db_64         rez_code;
   struct db_64s        rez_codes;
   struct mag_code      MAG_code;
   struct rem_zond_code REM_zond_code;
   struct sf_code       SF_code;
   struct ccc_code      CCC_code;
   struct mbl_code      MBL_code;
   struct eval_code     EVAL_code;
   struct emi_code      EMI_code;
   struct orcode        OR_code;
   struct time_count_codes COUNTER_codes;
   imp_count_codes      iCOUNTER_codes;
   struct mark_code     MRK_code;
   struct diag_code     DiagCode;
   struct diag_code_IP4ping DiagCodePing;
   struct opcm_code     OPCM_code;
   struct file_uso_code FDAT_code;
   struct elec_code     ELEC_code;
   };

struct current_value {                 /* шаблон текущего значения */
   short cdval;                        /* current value ADC code  | код текущего значения  */
   short prev_code;                    /* previous value ADC code | код за предыдущий цикл */
   };

#pragma pack (1)
 struct ZondNamesDBF
  { char full_name[MAXLENNAME];         /* полное наименование параметра */
    char code[2][MAX_PARAMCODE_LEN];    /* коды параметров по классифик. */
  };                                    /* size of struct 114 bytes      */
#pragma pack ()

                /* Значения valtype                           */
#define TYPE_LOCAL      0   /*     0 - внутренний (местный, УСОвый)       */
#define TYPE_MANUAL     1   /*     1 - ручной ввод                        */
#define TYPE_EXTERN_SET 2   /*     2 - задаваемый извне                   */
#define TYPE_EXTERN_CON 3   /*     3 - управляемый извне                  */

#ifdef EXEC95  //!!!OLEG2!!!
 #define LocalOrExtcon (lpS->valtype == TYPE_LOCAL ||      \
                lpS->valtype == TYPE_EXTERN_CON)
 #define ManualOrExtset (lpS->valtype == TYPE_MANUAL ||    \
                lpS->valtype == TYPE_EXTERN_SET)
 #define LocalOrManual (lpS->valtype == TYPE_LOCAL ||      \
                lpS->valtype == TYPE_MANUAL)
 #define ExtsetOrExtcon(sys) (lpS->valtype == TYPE_EXTERN_SET ||      \
                lpS->valtype == TYPE_EXTERN_CON)
#else
 #define LocalOrExtcon(sys) ((status+(sys))->valtype == TYPE_LOCAL ||      \
                (status+(sys))->valtype == TYPE_EXTERN_CON)
 #define ManualOrExtset(sys) ((status+(sys))->valtype == TYPE_MANUAL ||    \
                (status+(sys))->valtype == TYPE_EXTERN_SET)
 #define LocalOrManual(sys) ((status+(sys))->valtype == TYPE_LOCAL ||      \
                (status+(sys))->valtype == TYPE_MANUAL)
 #define ExtsetOrExtcon(sys) ((status+(sys))->valtype == TYPE_EXTERN_SET ||      \
                (status+(sys))->valtype == TYPE_EXTERN_CON)
 #define SwEquipCondOk(sys) (*((unsigned int *)(status+(sys))) >= MINSTATUS)
#endif

struct param_status {         /*     0            1                         */
/* 0*/ unsigned typ    : 4;   /*   analog      discrete                     */
/* 4*/ unsigned hist   : 1;   /* not collect     collect      avg.history   */
/* 5*/ unsigned siren  : 1;   /* siren sound off on                         */
/* 6*/ unsigned alarm  : 1;   /* warning         alarm                      */
/* 7*/ unsigned kvit   : 1;   /* !!! not квитир.    квитировано нарушение   */
/* 8*/ unsigned grf    : 1;   /*    no           yes      in file .grh      */
/* 9*/ unsigned contrInProgress: 1; /* control time duration                */
                              /* подали команду управления, следим за временем */
/*10*/ unsigned valtype: 2;   /* см define TYPE_xxx                         */
/*12*/ unsigned Marked4Control: 1;  /* невыб выбран для управления          */
/*13*/ unsigned grh    : 1;   /* not need        need     in trend file .grh   */
/*14*/ unsigned co_eq_sw : 1; /* previous | of 29-31 bits (sw|equip|cond)   */
/*15*/ unsigned intcgroup : 1; /* 1 - param in tc group                     */
/*16*/ unsigned tcgroup : 4;  /* control rights group, strongly - pasport part */
                              /* see also CNT_RIGHT_GR_NUM                  */
/*20*/ unsigned b20_24 : 8;
/*28*/ unsigned trust  : 1;   /* !!! val true      val not trust            */
/*29*/ unsigned cond   : 1;   /* неисправен    исправен                     */
/*30*/ unsigned equip  : 1;   /* выключен      включен техн. аппарат        */
/*31*/ unsigned sw     : 1;   /* permit запрещена  allow разрешена обработка*/
  };                          /* !!! - race (sbor,eval,HMI)                 */

union PSTATUS {
  struct param_status  status;
  int                  db_32;
};

#define MINSTATUS  0xE0000000 /* min status treatment value (sw|equip|cond|?) | минимальный статус работоспособного датчика */
#define MINSTATUSR 0xF0000000 /* min status trust value (sw|equip|cond|trust) | минимальный статус достоверного значения */

enum GRAD {
        LN,     KB,     GR20,   GR21,   GR22,   GR23,   GR24,   TXK,
    TXA,    TPP,    NS1,    NS2,    NS3,    NS4,    NS5,    MAG,
    MAX_GRAD };

enum _DIRECTION_OF_PRINTING_ {
        NONE_PRINT,
        SCREEN_WINDOW,
        STANDART_PRN,
        BOTH };

struct ParamNSI
 { union  PASPORT       Pasp;
   struct param_status  Status;
   union  CODE          Codes;
   struct ZondNamesDBF  Names;
 };

struct CODEnPSTATUS
{ union CODE c;
  struct param_status s;
};

union UniValues     // union values for universal data storage
  { int    i;
    float  f;
    double d;
  };

// developing of FALSE==0, TRUE==ADC_TYPE==1, ... - GetValue ret code
enum ValuesTypes
{ ADC_TYPE = 1,     // 12 bit adc code
  FLOAT_TYPE,
  DOUBLE_TYPE,
  INT_TYPE,
  ADC16_TYPE        // 16 bit adc code (06.08 to remain accuracy if such code may be get from uso)
};

struct _tz_value
{ union UniValues value;  /* value */
  unsigned char   type;   /* enum ValuesTypes see "patterns.h" */
  unsigned char   trust;  /* may be TRUE/FALSE */
};

/* Sbor get value methods.--------------------------------------------------*/
struct _sbor_get_values
{ int (* UsoGetCurrentValue)(int uso,int sys,int base_type,int bits,int *cur_val);
  int (* GetExtValue)(int sys, int *trust, void *value);  /* TYPE_MANUAL or TYPE_EXTERN_SET */
  int (* LockValueCache) (void);    /* lock/unlock for TWIN value cache i/o sync */
  int (* UnlockValueCache) (void);
};

extern struct _sbor_get_values g_Sbor;

/*--------------------------------------------------------------------------*/
 extern int  g_SimMode;      /* option SIMULATE, see initsbor.c */

 struct _sine_sin_mode       /* option SINESIMULATE, ... */
  { int  enable;
    int  amplitude;
    int  discret_manual;
  };
 extern struct _sine_sin_mode g_SineSimMode;  /* option SINESIMULATE, ... */

 extern struct ZOND_VERSION      g_rZondVersion;/* Номер версии exe-файла  */
 extern unsigned char            g_MinorVersion;/* minor ver letter */
 extern int                      start_flags;
 extern struct an_pasport *      pasp;      /* указатель на массив паспортов */
 extern union PASPORT *          BlankPasport[16]; /* Массив указ. на пустышки */
 extern const union PSTATUS      BlankStatus;

//#ifdef __SC__
// extern char * path_to_workdir_ptr;	   /* путь к рабочей директории "Зонд"-а */
// extern char * path_to_database_ptr;        /* путь к директории БД */
// extern struct ZOND_VIZA_CONFIG  conf;      /* конфигурация */
// extern struct DynamicFlags Dflags;
// extern union CODE *             codes;
// extern struct param_status *    status;    /* указатель на массив статусов  */

//#else  /* MSC - Для сборки 16 разрядных программ */

// extern struct ZOND_VIZA_CONFIG near conf;
// struct param_status * near      status;
// extern union CODE huge * near   codes;
//#endif  /* __SC__ */

 extern char                     SirenStatus;      /* Состояние сирены */
 extern double                   g_gelta_t;        /* Период обработки в часах */
 extern int                      SaveZondDb;       /* save "zond.db" query flag */
 extern int                      SaveZondTmp;      /* save "zond.tmp" query flag */
#ifdef WIN32
 extern int ZondDbSaved;
 extern int ZondTmpSaved;
#endif // WIN32
 extern struct current_value *   tz;
 extern double *                 mn;
 extern double *                 DoubleValue;

#pragma pack(1)
 struct RazmTable44 /* ver 4.40 - data block in "zond.db" */
  { char razm_strings[MNRAZM_44][MCHRAZM_44];
  };

 struct RazmTable   /* ver 4.50 - memory block, data in "dimens.xml "*/
  { char razm_strings[MAXNRAZM][MAXCHRAZM];
  };
#pragma pack()

 extern struct RazmTable         gDefRazmTable;    /* default razm table (base) */
 extern char *                   razm[MAXNRAZM];   /* array ptr's to names      */

 extern void *                   sys_error_window; /* error window (red & yellow) */
 extern void *                   message_window;   /* protocol window (black & yellow) */
#ifdef  __SC__
 extern MSGBUF *                 sys_error_msgbuf; /* просмотр "Тех. сообщений" */
#endif  /* __SC__ */
 extern int                      sys_window_active;
 extern int                      window_sem;
 extern char                     config_file_name[_MAX_PATH];
 extern char                     ppir;
 extern char *                   ADRAP;
 extern char *                   tsca_tscp[2];
 extern char *                   ADRTSCA;
 extern char *                   ADRTSCP;

#define ONE_ANALOG_COL_NUM_44 8    /* colors in table */
#define ANALOG_COL_NUM_44     1    /* tables */
#define ONE_DISCR_COL_NUM_44  9    /* colors in table */
#define DISCR_COL_NUM_44      8    /* tables */

 enum ANALOG_COLORS_INDEXES
  { ACI_NVG,
    ACI_NAG,
    ACI_NTG,
    ACI_NORMA,
    ACI_VTG,
    ACI_VAG,
    ACI_VVG,
    ACI_TRUST,    /* not trust color index */
    ACI_SW,
    ACI_COND,
    ACI_EQUIP,
    ACI_MANUAL,
    ONE_ANALOG_COL_NUM_45
 };
#define ANALOG_COL_NUM_45     8    /* tables */

 enum DISCRET_COLORS_INDEXES
  { DCI_S0,
    DCI_S1,
    DCI_S2,
    DCI_S3,
    DCI_S4,
    DCI_S5,
    DCI_S6,
    DCI_S7,
    DCI_TRUST,    /* not trust color index */
    DCI_SW,
    DCI_COND,
    DCI_EQUIP,
    ONE_DISCR_COL_NUM_45
  };
#define DISCR_COL_NUM_45      8    /* tables */

#pragma pack(1)
 struct Acolor44
  { short Analog_Colors[ANALOG_COL_NUM_44][ONE_ANALOG_COL_NUM_44];
  };

 struct Dcolor44
  { short Discr_Colors[DISCR_COL_NUM_44][ONE_DISCR_COL_NUM_44];
  };

 struct ColorTable44              /* ver 4.40 - data block in "zond.db" */
  { struct Acolor44   ac;
    struct Dcolor44   dc;
  };

#define CR_USE_RGB  -1
 struct _color_ref
  { char          idx;            /* color index in DOS table, if CR_USE_RGB use RGB */
#ifdef  _WIN32
    char          align0;
    short         align1;
    unsigned long rgb;            /* WIN RGB color */
#endif
  };

 struct ColorTable                /* ver 4.5 - file "colors.xml" */
  { struct _color_ref ac[ANALOG_COL_NUM_45][ONE_ANALOG_COL_NUM_45];
    struct _color_ref dc[DISCR_COL_NUM_45][ONE_DISCR_COL_NUM_45];
  };
#pragma pack()

 extern struct ColorTable gDefColorTbl; /* default color tables (base) */
 extern struct ColorTable gColorTbl;    /* current color table */

 extern int    printer_port;      /* q-порт протокольного принтера */
 extern int    add_printer_port;  /* q-порт дополнительного принтера */
 extern int        monitor_id;
 extern int        save_bd_pid;
 extern int        save_exit;
 extern int        sbor_sem;
 extern int        uso_sbor_sem;  // Semaphore, used to sync. sbor & USO stopping
 extern int        uso_hmi_sem;	  // Semaphore, used to sync. HMI thread & USO stopping
#ifdef WIN32
  extern int       usermain_exit;
  #define zond_working()  (!usermain_exit)
#else
  #define zond_working()  (monitor_id > 0)
#endif
 extern union  PASPORT *         Sbor_inspasp;     /* ptr to current treat pasport (used in "sbor") */
#ifndef WIN32
 extern union  PASPORT           Correct_inspasp;
#endif
 extern int                      CopyFileSem;      /* "commands" semaphore */
 extern const char               mes_form[];       /* "#%5d %-14s %s %s" */
 extern char                     GroupsPath[];     /* путь к файлу GROUPS. */
 extern char                     NamesPath[];      /* путь к файлу NAMESPRM.DBF */
#ifndef WIN32
 extern char                     FntPath[];
 extern int                      last_font;
#endif
 extern short                    MagistralPassword; /* "Mag-1" password */

 extern T_QWORD AcqLastTicks;    /* продолжительность последней обработки */
 extern T_QWORD AcqMinTicks;     /* минимальное время обработки в тиках   */
 extern T_QWORD AcqMaxTicks;     /* максимальное время обработки в тиках  */
 extern T_QWORD CycleTicks;      /* измеренный цикл, как его выдержал asyn_timer */

 extern unsigned long g_zond_tmp_save_time; /* "zond.tmp" saving time */
 extern unsigned long g_zond_db_save_time;  /* "zond.db" saving time */

/*--------------------------------------------------------------------------*/
#pragma pack (1)
 struct FileDummyFlags
  { BIT_FIELD ContrPermission  : 1;     /* Делегированы ли права управления */
    BIT_FIELD SMsDisable       : 1;     /* disable SMS from diag */
    BIT_FIELD reserv           :14;
    unsigned long              ContrPermissionGroupMask;
  };
 struct FileDummyStruct
  { char StopTimeStr[21];               /* Строка с временем останова */
    char reserv;
    struct FileDummyFlags flags;
  };

#pragma pack (4)

 extern struct FileDummyStruct DummyFile;        /* "dummy.tim" file format */
 extern int                    file_dummy;       /* "dummy.tim" file open handle */

#ifdef WIN32
 #define ZND_CALL enum T_ZE_NUMBERS
#else
 #define ZND_CALL enum T_ZE_NUMBERS pascal
#endif /*_WIN32*/

#ifdef  __SC__
#define PENTRYINFO struct _param_entry_info_
 struct _param_entry_info_
  { unsigned int q_level;       /* Number of levels in connection Число используемых уровней в подключении */
    unsigned int dir;           /* Direction number Номер направления            - уровень 0 */
    unsigned int plc;           /* Controller number Номер контроллера            - уровень 1 */
    unsigned int addr;          /* Adress Адрес (плата, и т.п.)        - уровень 2 */
    unsigned int subaddr;       /* SubAdress Подадрес                     - уровень 3 */
    unsigned int subsubaddr;    /* ...  Подподадрес                  - уровень 4 */
    unsigned int subsubsubaddr; /* Подподадрес                  - уровень 5 */
    unsigned int uso;           /* Number of USO номер USO см. enum Uso_Types             */
  };                            /* sizeof struct 32 bytes                   */

#define PENTRYINDEX struct _param_entry_indexed_
 struct _param_entry_indexed_
  { unsigned int q_level;       /* Число используемых уровней в подключении */
    unsigned int lev[6];        /* уровень 0 ... 5                          */
    unsigned int uso;           /* номер USO см. enum Uso_Types             */
  };                            /* sizeof struct 32 bytes                   */

#define UPENTRYINFO union _param_entry_union_
 union _param_entry_union_
  { PENTRYINFO  addr;           /* по именам */
    PENTRYINDEX lev;            /* по уровням через индексы */
  };

#define USOEXFUNC struct _USO_ex_functions_
 struct _USO_ex_functions_
  { ZND_CALL (*GetParamEntry) (int sys, PENTRYINFO *p); /* Уровни подключения */
    ZND_CALL (*GetParamEntryName) (char *name,int namelen,PENTRYINFO *entry,
                 int level);
    ZND_CALL (*GetLevelName) (char *name,int namelen,int level);
  };

                      /* Что может отдавать Slave */
#define SL_VALUE_MSK    0x00000001L   /* адрес значение параметра */
#define SL_TRUST_MSK    0x00000002L   /* признак достоверности */
#define SL_KVIT_MSK     0x00000004L   /* признак квитирования */
#define SL_CONTROL_MSK  0x00000008L   /* управление */
#define SL_UST_NVG_MSK  0x00000010L   /* нижняя возможная граница */
#define SL_UST_NAG_MSK  0x00000020L   /* нижняя аварийная граница */
#define SL_UST_NTG_MSK  0x00000040L   /* нижняя техн-ская граница */
#define SL_UST_VTG_MSK  0x00000080L   /* верхняя технологическая граница */
#define SL_UST_VAG_MSK  0x00000100L   /* верхняя аварийная граница */
#define SL_UST_VVG_MSK  0x00000200L   /* верхняя возможная граница */
#define SL_NGRA_MSK     0x00000400L   /* номер нарушенной границы */

#define SLEXFUNC struct _SL_ex_functions_
 struct _SL_ex_functions_
  { unsigned long       value_msk;    /* какие типы значений может отдавать */
                      /* SL_xxxxx_MSK|...                   */
    unsigned long       par_types;    /* типы параметров, которые может     */
                      /* отдавать: MASK_ANALOG,MASK_DISCR.. */
    ZND_CALL (*SlGetParamEntry) (int sys,       /* Уровни подключения       */
                 unsigned long  value_msk,PENTRYINFO *p);
    ZND_CALL (*SlGetParamEntryName) (char *name, /* название уровней        */
                 int namelen,PENTRYINFO *entry,int level);
  };
#endif  /* __SC__ */

 extern void *MainProcHandle;   // Идентификатор главного процесса в Winde
                // при просмотре паспортов

 extern unsigned int delta_freq,start_freq,end_freq;  // Управление сиреной

#define  VOID_VALUE     0

#pragma pack ()

// Zond GUI settings
#define PROT_WINDOWS_FONTSIZE_MIN 9
#define PROT_WINDOWS_FONTSIZE_DEF 12  // default
#define PROT_WINDOWS_FONTSIZE_MAX 60

#endif  /* __PATTERNS__ */

#ifdef SIZE_TEST
void main (void)
 { printf ("Sizeof conf    %d\n",sizeof(struct ZOND_VIZA_CONFIG));
   printf ("Sizeof pasport %d\n",sizeof(union PASPORT));
   printf ("Sizeof analog  %d\n",sizeof(struct an_pasport));
   printf ("Sizeof discr   %d\n",sizeof(struct dis_pasport));
   printf ("Sizeof npos    %d\n",sizeof(struct npos_pasport));
   printf ("Sizeof 8bit    %d\n",sizeof(struct discr_8bit));
   printf ("Sizeof meter   %d\n",sizeof(struct meter_line));
   printf ("Sizeof meter_p %d\n",sizeof(struct meter_pipe));
   printf ("Sizeof status  %d\n",sizeof(struct param_status));

   printf ("Size of union CODE %d\n",sizeof(union CODE));
   printf ("Sizeof ccc_code  %d\n",sizeof(struct ccc_code));
   printf ("Sizeof mbl_code  %d\n",sizeof(struct mbl_code));
   printf ("Sizeof struct ParamFlags %d\n",sizeof(struct ParamFlags));
   printf ("Sizeof struct orcode %d\n",sizeof(struct orcode));

   printf ("Sizeof struct ZOND_VERSION %d\n",sizeof(struct ZOND_VERSION));
 }
#endif  /* SIZE_TEST */
