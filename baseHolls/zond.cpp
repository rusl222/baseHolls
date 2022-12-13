#include "zond.h"
#include "patterns.h"


using namespace filesystem;

Zond::Zond()
{
}





/*---------------------   Serialization   -----------------*/
ifstream& operator>>(ifstream& d, CODE& c){
    d.read(reinterpret_cast<char*>(&c), sizeof(CODE));
    return d;}
ofstream& operator<<(ofstream& d, const CODE& c){
    d.write(reinterpret_cast<const char*>(&c), sizeof(CODE));
    return d;}

ifstream& operator>>(ifstream& d, PASPORT& p){
    d.read(reinterpret_cast<char*>(&p), sizeof(PASPORT));
    return d;}
ofstream& operator<<(ofstream& d, const PASPORT& p){
    d.write(reinterpret_cast<const char*>(&p), sizeof(PASPORT));
    return d;}


/*----------------------------------------------------------*/

// ����� ����� � zond.db
// minCnt - ����������� ���������� ������
 list <string> Zond::getHoles(path zdbFilePath, long minCnt)
{
	 list <string> textList;
    long cnt=0;
    CODE ec;
	
	if (!exists(zdbFilePath))
	{
		textList.push_back("���� �� ������");
		return textList;
	}

	FILE *file;

	if (fopen_s(&file,zdbFilePath.string().c_str(),"rb"))
	{
		textList.push_back("������ ��������");
		return textList;
	}

    ifstream zdb(file);

    long long   lTotalItems = (file_size(zdbFilePath) - (sizeof(RazmTable44)+ sizeof(ColorTable44)))/(sizeof(CODE) + sizeof(PASPORT) + sizeof(PSTATUS));
    textList.push_back ("������ ��: " + to_string(lTotalItems) + ". ������ ������:");

    long i;
    for (i=0;i<lTotalItems;i++) {
        zdb >> ec;
        if(ec.EVAL_code.rezerv==1){
            cnt++;
        }
        else {
            if (cnt >= minCnt) {
                textList.push_back( "c " + to_string(i-cnt) + " �� " + to_string(i-1) +
                        " �����: " + to_string(cnt));
            }
            cnt=0;
        }
    }

    if (cnt >= minCnt) {
        textList.push_back("c " + to_string(i-cnt) + " �� " + to_string(i-1) +
                " �����: " + to_string(cnt));
    }
    fclose(file);
    return  textList;
 }


 /*
 QStringList Zond::getParam(QString findText,QString zdbFilePath, QString namesFileName="" )
 {
    QStringList textList;

    QFile zdbfile(zdbFilePath);
    if (!zdbfile.exists()) return QStringList("���� zond.db �� ������");

    QFile nfile(namesFileName);
    if (!nfile.exists()) return QStringList("���� namesprm.dbf �� ������");

    QDataStream zdb(&zdbfile);
    zdb.setByteOrder(QDataStream::LittleEndian);
    if (!zdbfile.open(QIODevice::ReadOnly)) return QStringList("������ ��������");
    if( zdb.status()!=0) return QStringList("������ " +  QString::number(zdb.status()));

    long long   lTotalItems = (zdbfile.size() - (sizeof(RazmTable44)+ sizeof(ColorTable44)))/(sizeof(CODE) + sizeof(PASPORT) + sizeof(PSTATUS));
    //textList << "������ ��: " + QString::number(lTotalItems) + ". �����:";






    return textList;
 }*/



/*-------------------------  ������ ����� zond.db -------------------------*/
/*
 enum T_ZE_NUMBERS ReadZondDbPath2 (QString path, int maxcodes,
                 union CODE *p_codes, union PASPORT *p_pasp,
                 struct param_status *p_status,char *p_razm)

 {

     CODE ec;

     QFile file(path);
     if (!file.exists()) return ZE_FNF;

     QDataStream zdb(&file);
     zdb.setByteOrder(QDataStream::LittleEndian);
     if (!file.open(QIODevice::ReadOnly)) return ZE_OPENF;
     if( zdb.status()!=0) return ZE_OPENF;

     //long long   lTotalItems = (file.size() - (sizeof(RazmTable44)+ sizeof(ColorTable44)))/(sizeof(CODE) + sizeof(PASPORT) + sizeof(PSTATUS));


     zdb.readRawData((CODE *)p_codes, maxcodes);

     for (long i=0;i<maxcodes;i++) {
         zdb >> ec;
         if(ec.EVAL_code.rezerv==1){
             cnt++;
         }
         else {
             if (cnt > minCnt) {
                 textList << "c " + QString::number(i-cnt) + " �� " + QString::number(i-1) +
                         " �����: " + QString::number(cnt);
             }
             cnt=0;
         }
     }
     file.close();



     return(ZE_OK);
 }
*/

/*-------------------------  --------------------- -------------------------*/






