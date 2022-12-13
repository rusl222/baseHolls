#ifndef ZOND_H
#define ZOND_H

#include "patterns.h"
#include <list>
#include <fstream>
#include <string>
#include <filesystem>


using namespace std;

class Zond
{

public:
    Zond();

    // Открытие файла

    enum T_ZE_NUMBERS ReadZondDbPath2 (filesystem::path path1, int maxcodes,
                    union CODE *p_codes, union PASPORT *p_pasp,
                    struct param_status *p_status,char *p_razm);



    // Поиск дырок в БД
    list <string> getHoles(filesystem::path zdbFilePath, long minCnt);

    // Поиск параметров по реперу и наименованию(их части)
    list <string> getParam(string findText, string zdbFilePath, string namesFileName );



};

#endif // ZOND_H
