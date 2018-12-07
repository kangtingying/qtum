
#include "qt/multisignpage.h"
#include "qt/forms/ui_multisignpage.h"
#include <QProcess>
#include <QJsonParseError>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QJsonArray>
#include <QInputDialog>

#include <QThread>
#include <QDir>
#include "openssl/md5.h"
#include <memory>
#include <util.h>
#include "rpcconsole.h"




//2: 2-2 3: 2-3
#define MULTISIGNMODEL 3
//1: testnet 0:
#define TESTNETWORK  0
static void printLog(const char *str)
{
    QString fPath = QDir::homePath()+"/multisig.log";
    QFile f(fPath);
    if(!f.open(QIODevice::Append)){
        return;
    }
    f.write(str);
    f.close();
}
static uchar  spcCharToHex (uchar  cIn)
{
    if ((cIn >= '0') && (cIn <= '9')) {
        return (cIn - '0');
    } else if ((cIn >= 'a') && (cIn <= 'f')) {
        return (cIn - 'a' + 10);
    } else if ((cIn >= 'A') && (cIn <= 'F')) {
        return (cIn - 'A' + 10);
    } else {
        return (-1);
    }
}


static int  spcStringToHex (uchar  *ucOutData, uchar  *cString, int  iLen)
{
    uchar  *cData = cString;
    int    iInIndex  = 0;
    int    iOutIndex = 0;
    for (iInIndex = 0; iInIndex < iLen; iInIndex++) {
        if((iInIndex % 2) == 0) {
            //
            *(ucOutData + iOutIndex) |= (spcCharToHex(*(cData + iInIndex)) << 4);
        } else {
            //
            *(ucOutData + iOutIndex) |= (spcCharToHex(*(cData + iInIndex)));
            iOutIndex++;
        }
    }
    return (iInIndex);
}


static int  spcPacketSendData (unsigned char  *ucData, SPC_SEND_DATA_T  *pSendData)
{
    int              i;
    int              sRet;
    uint16_t           usHexLong;
    uint16_t           usIndex = 0;
    ucData[usIndex++] = 0xa1;
    usIndex += 2;
    ucData[usIndex++] = 0xba;
    sRet = spcStringToHex(ucData + usIndex + 2, pSendData->pcTransaction, strlen((const char *)(pSendData->pcTransaction)));
    usHexLong = (sRet / 2) + (sRet % 2);
    if (sRet % 2) {
        usHexLong |= 0x8000;
    }
    memcpy(ucData + usIndex, &usHexLong, 2);
    usIndex = usIndex + 2 + (usHexLong & 0x7FFF);

    ucData[usIndex++] = 0xca;
    ucData[usIndex++] = 0;
    ucData[usIndex++] = 0;
    ucData[usIndex] = pSendData->ucTxidArrayNum;
    usIndex++;
    for (i = 0; i < pSendData->ucTxidArrayNum; i++) {

        sRet = spcStringToHex(ucData + usIndex + 1, pSendData->pcTxid[i], strlen((const char *)(pSendData->pcTxid[i])));

        usHexLong = (sRet / 2) + (sRet % 2);
        if (sRet % 2) {
            usHexLong |= 0x80;
        }

        *(ucData + usIndex) = usHexLong & 0xFF;
        usIndex = usIndex + 1 + (usHexLong & 0x7F);

        ucData[usIndex] = pSendData->ucVout[i];
        usIndex++;
        sRet = spcStringToHex(ucData + usIndex + 2, pSendData->pcScriptPubKey[i], strlen((const char *)(pSendData->pcScriptPubKey[i])));

        usHexLong = (sRet / 2) + (sRet % 2);
        if (sRet % 2) {
            usHexLong |= 0x8000;
        }
        memcpy(ucData + usIndex, &usHexLong, 2);
        usIndex = usIndex + 2 + (usHexLong & 0x7FFF);

        sRet = spcStringToHex(ucData + usIndex + 2, pSendData->pcRedeemScript[i], strlen((const char *)(pSendData->pcRedeemScript[i])));

        usHexLong = (sRet / 2) + (sRet % 2);
        if (sRet % 2) {
            usHexLong |= 0x8000;
        }
        memcpy(ucData + usIndex, &usHexLong, 2);
        usIndex = usIndex + 2 + (usHexLong & 0x7FFF);
    }
    memcpy(ucData + usIndex, &pSendData->uiPrivKeyIndex, 2);
    usIndex += 2;

    ucData[usIndex] = 0x1a;
    memcpy(ucData + 1, &usIndex, 2);

    return (0);
}


static char ConvertHexChar(char ch)
{
    if((ch >= '0') && (ch <= '9'))
        return ch-0x30;
    else if((ch >= 'A') && (ch <= 'F'))
        return ch-'A'+10;
    else if((ch >= 'a') && (ch <= 'f'))
        return ch-'a'+10;
    else return (-1);
}


static void StringToHex(QString str, QByteArray &senddata)
{
    int hexdata,lowhexdata;
    int hexdatalen = 0;
    int len = str.length();

    char lstr,hstr;

    if((len & 0x0001) > 0){
        senddata.resize(len/2+1);
    }else{
        senddata.resize(len/2);
    }

    for(int i=0; i<len; )
    {
        //char lstr,
        hstr=str[i].toLatin1();
        if(hstr == ' ') {
            i++;
            continue;
        }

        i++;
        if(i >= len)
            break;

        lstr = str[i].toLatin1();

        hexdata = ConvertHexChar(hstr);
        lowhexdata = ConvertHexChar(lstr);

        if((hexdata == 16) || (lowhexdata == 16))
            break;
        else
            hexdata = hexdata*16+lowhexdata;
        i++;
        senddata[hexdatalen] = (char)hexdata;
        hexdatalen++;
    }
    senddata.resize(hexdatalen);
}


MultiSignPage::MultiSignPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    cTxid(0),
    vout(-1),
    index(100),
    ui(new Ui::MultiSignPage)
{
    ui->setupUi(this);
    init();
}
MultiSignPage::MultiSignPage(QWidget *parent) :
    QDialog(parent),
    cTxid(0),
    vout(0),
    ui(new Ui::MultiSignPage)
{
    ui->setupUi(this);

}

MultiSignPage::~MultiSignPage()
{
    delete ui;
}

void MultiSignPage::setClientModel(ClientModel *clientModel)
{

}
void MultiSignPage::setModel(WalletModel *model)
{
}

void MultiSignPage::init()
{
    //read server,account,passwd
    cTxid = NULL;
    QString cfgPath = QDir::homePath() + "/email.ini";
    QFile f(cfgPath);
    if(f.open(QIODevice::ReadOnly)){
         int i = 1;
	QByteArray line;
         while(!f.atEnd()){
             line = f.readLine();
             if(QString(line).startsWith("server=")){
                server = QString(line).mid(7);
                server.chop(1);
             }
             if(QString(line).startsWith("address=")){
                 account = QString(line).mid(8);
                account.chop(1);
             }
             if(QString(line).startsWith("passwd=")){
                 passwd = QString(line).mid(7);
                passwd.chop(1);
             }
         }
    }
    f.close();
    QString emailTmpDir = QDir::homePath().append("/emailtmp");
    QDir dir;
    if(!dir.exists(emailTmpDir)){
        dir.mkpath(emailTmpDir);
    }
    connect(this, SIGNAL(packetData()),this, SLOT(on_packetData()));
}

void MultiSignPage::on_generateButton_clicked()
{
    char cmd[512]={0};
    char *secondAddress = NULL;
    if((ui->importLineEdit->text().isEmpty())||(ui->satAddressLineEdit->text().isEmpty())||(ui->thirdAddressLineEdIt->text().isEmpty()))    return;

    QByteArray arrayFirst = ui->importLineEdit->text().trimmed().toLatin1();
    char *firstAddress = arrayFirst.data();
    //get real satllite address
    QString strSatlliteAddress = ui->satAddressLineEdit->text().trimmed();
    QString realSatlliteAddress = strSatlliteAddress.left(strSatlliteAddress.length()-2);
    QString strIndex = strSatlliteAddress.right(2);
    this->index = strIndex.toInt();
    QByteArray tmpRealSatlliteAddressByarray = realSatlliteAddress.toLatin1();
    secondAddress = tmpRealSatlliteAddressByarray.data();
    char *thirdAddress = NULL;
    QByteArray arrayThird = ui->thirdAddressLineEdIt->text().trimmed().toLatin1();
    thirdAddress = arrayThird.data();

    if(int(MULTISIGNMODEL)==2){
            sprintf(cmd, "addmultisigaddress 2 \"[\\\"%s\\\",\\\"%s\\\"]\"", firstAddress, secondAddress);
    }else{
            sprintf(cmd, "addmultisigaddress 2 \"[\\\"%s\\\",\\\"%s\\\",\\\"%s\\\"]\"", firstAddress, secondAddress,thirdAddress);
    }
    std::string t;
    DoCommand doCommandMultisig(cmd);
    t = doCommandMultisig.getReturnFromStdOutPut();

    QJsonParseError error;
    QJsonDocument document = QJsonDocument::fromJson(QString::fromUtf8(t.c_str()).toUtf8(), &error);
    if(QJsonParseError::NoError == error.error){
        QVariantMap map = document.toVariant().toMap();
        if(map.contains("address")) {
            QString addr = map["address"].toString();
            this->multisigAddress = addr.toStdString();
            ui->multisigAddressLineEdit->setText(addr);
        }
        if(map.contains("redeemScript")){
            QString redeemScriptcriptAddr = map["redeemScript"].toString();
            this->redeemScript = redeemScriptcriptAddr.toStdString();
            //ui->redeemScripTextEdit->setText(redeemScriptcriptAddr);
        }
    }
}

void MultiSignPage::on_emailButton_clicked()
{
    QString cfgPath = QDir::homePath() + "/email.ini";
    QFile ff(cfgPath);
    if(ff.open(QIODevice::ReadOnly)){
	QByteArray line;
         while(!ff.atEnd()){
             line = ff.readLine();
	     if(QString(line).startsWith("server=")){
                 server = QString(line).mid(7);
		 server.chop(1);
             }
             if(QString(line).startsWith("address=")){
                 account = QString(line).mid(8);
		account.chop(1);
             }
             if(QString(line).startsWith("passwd=")){
                 passwd = QString(line).mid(7);
		passwd.chop(1);
             }
         }
    }
    ff.close();
#if 1
    bool ok;
    if(sTxid.empty())	return;
    QString sPwd = QInputDialog::getText(this, tr("输入卫星多签口令"), tr("卫星多签口令:"), QLineEdit::Password, "", &ok);
    if (!ok){
        return;
    }
    char mdStr[17] = {0};
    QByteArray passwdLatin = sPwd.toLatin1();
    char *in = passwdLatin.data();
    MD5((uchar *)in,passwdLatin.size(),(uchar *)mdStr);  
    if(!on_packetData()) return;    //write to attachment
    //packet txid and mdStr together
    std::unique_ptr<uchar> pToWrite(new uchar[sTxid.size()+16]());
    memcpy(pToWrite.get(),(sTxid.c_str()), sTxid.size());
    memcpy((uchar *)(pToWrite.get()+sTxid.size()),(uchar*)(mdStr),16);
    MD5(((uchar*)pToWrite.get()),(sTxid.size()+16),(uchar *)mdStr);
    QFile f(QDir::homePath()+"/encryption.bin");
    if(!f.open(QIODevice::WriteOnly)){
        return;
    }
    f.write(mdStr, 16);
    f.close();
    //send attachment
    QFileInfo f1(QDir::homePath()+"/encryption.bin");
    QFileInfo f2(QDir::homePath()+"/spcdata.bin");
    if((!f1.exists())||(!f2.exists())){
        return;
    }
#endif

#ifndef WIN32
    QProcess sendProcess;
    QString s = account +" " + passwd + " " + (QDir::homePath() + "/encryption.bin") + " " + (QDir::homePath()+"/spcdata.bin") + " " + QString(SATELLITEEMAIL);
    QString t = QString("python3 ") + QDir::currentPath()+QString("/tool.py ");
    sendProcess.start(t + s);
    sendProcess.waitForStarted();
    sendProcess.waitForFinished();
#else
    QProcess p;
    QStringList argv;
    argv << account << passwd << (QDir::homePath() + "/encryption.bin") << (QDir::homePath()+"/spcdata.bin") << QString(SATELLITEEMAIL);
    p.start((QDir::currentPath()+QString("/tool.exe")),argv);
    p.waitForStarted();
    p.waitForFinished();
    return;
#endif
}
//transaction fee 0.1
static double deductFee(QString fee)
{
    double f = fee.toDouble();
    uint64_t t = f*1000000;
    return (t-100000)/1000000.0;
}
void MultiSignPage::on_signButton_clicked()
{
    if((ui->fromAddressLineEdit->text().isEmpty())||(ui->toAddressLineEdit->text().isEmpty())||(ui->amountLineEdit->text().isEmpty()))    return;
    if((this->privKey = importPrivKey(ui->importLineEdit->text().toStdString())).empty()){
        return;
    }
    //transfer to multisignadddress
    QByteArray bFrom = ui->fromAddressLineEdit->text().trimmed().toLatin1();
    char *multisignAddress = bFrom.data();
    QByteArray bAmount = ui->amountLineEdit->text().trimmed().toLatin1();
    char *amount = bAmount.data();

    char cmd[6000] = {0};
    sprintf(cmd, "sendtoaddress %s %s\n", multisignAddress, amount);
    DoCommand doCommandToMultisigAddress(cmd);
    std::string strTxid = doCommandToMultisigAddress.getReturnFromStdOutPut();
    sTxid = strTxid;
    if(strTxid.empty()) return;
    std::string rawTransaction;
    sprintf(cmd, "getrawtransaction %s\n", sTxid.c_str());
    std::string result;
    const std::string ccmd(cmd);
    RPCConsole::RPCExecuteCommandLine(result, ccmd);
    rawTransaction = result;
    sprintf(cmd, "decoderawtransaction %s\n", rawTransaction.c_str());
    const std::string decoderCmd(cmd);
    std::string rRawTransaction;
    RPCConsole::RPCExecuteCommandLine(result, decoderCmd);
    rRawTransaction = result;
    //cha * to json
    QJsonParseError error;
    QJsonDocument json = QJsonDocument::fromJson(QString::fromUtf8(rRawTransaction.c_str()).toUtf8(), &error);
    if(!json.isNull()||json.isEmpty()){
        if(json.isObject()){
            QJsonObject rootObj = json.object();
            if(rootObj.contains("vout")){
                QJsonValue valueArray = rootObj.value("vout");
                if(valueArray.isArray()){
                    QJsonArray jsonArray = valueArray.toArray();
                    for(int i =0; i<jsonArray.count();i++){
                        QJsonValue childValue = jsonArray[i];
                        if(childValue.isObject()){
                            QJsonObject childObject = childValue.toObject();
                            if(childObject.contains("scriptPubKey")){
                                QJsonValue valueJson = childObject.value("scriptPubKey");
                                if(valueJson.isObject()){
                                    QJsonObject lastObject = valueJson.toObject();
                                    if(lastObject.contains("addresses")){
                                        QJsonValue arrayAddress = lastObject.value("addresses");
                                        if(arrayAddress.isArray()){
                                            QJsonArray addressJsonValue = arrayAddress.toArray();
                                            for(int j = 0; j < addressJsonValue.count();j++){
                                                QJsonValue strAddress = addressJsonValue[j];
                                                QString tt = strAddress.toString();
                                                std::string ttt = tt.toStdString();
                                                if(strAddress.isString()){
                                                    //juge addess whether same;
                                                    QString t = strAddress.toString();
                                                    if(t.toStdString() == this->multisigAddress/*=*/){
                                                        QJsonValue nValue = childObject.value("n");
                                                        this->vout = nValue.toInt();
                                                        QJsonValue _scriptPubKeyHex = lastObject.value("hex");
                                                        if(_scriptPubKeyHex.isString()){
                                                            QString strScrip = _scriptPubKeyHex.toString();
                                                            this->scriptPubKeyHex = strScrip.toStdString();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        return;
    }

    //create transaction    std::string result;
    std::string transactionHex;
    if((transactionHex = createRawTransaction()).empty()){
        return;
    }
    std::string signRawTransactionHex;
    if((signRawTransactionHex = signRawTransaction(transactionHex, this->sTxid, this->vout, this->scriptPubKeyHex, this->redeemScript, this->privKey)).empty()){
        return;
    }
    //jiexi
    QString returnHex;
    json = QJsonDocument::fromJson(QString::fromUtf8(signRawTransactionHex.c_str()).toUtf8(), &error);
    if(QJsonParseError::NoError == error.error){
        QVariantMap map = json.toVariant().toMap();
        if(map.contains("hex")) {
            returnHex = map["hex"].toString();
            this->firstSigHex = returnHex;
            //printf("return Hex =%s|\n", this->firstSigHex.toStdString().c_str());
        }
    }
    char toSatelliteJson[6000] = {0};
    sprintf(toSatelliteJson, "%s \"[{\\\"txid\\\":\\\"%s\\\",\\\"vout\\\":%d,\\\"scriptPubKey\\\":\\\"%s\\\",\\\"redeemScript\\\":\\\"%s\\\"}]\" \"[\\\"\\\"]\"", returnHex.toStdString().c_str(), this->sTxid.c_str(), this->vout, this->scriptPubKeyHex.c_str(), this->redeemScript.c_str());
    ui->dataTextEdit->setText(QString::fromUtf8(toSatelliteJson));
}

std::string MultiSignPage::createRawTransaction()
{
    if(ui->toAddressLineEdit->text().isEmpty()) return NULL;
    char cmd[6000] = {0};
    std::string transactionHex;
    double at = deductFee(ui->amountLineEdit->text());
    QByteArray mb = QString::number(at).toLatin1();
    char *amount = mb.data();
    sprintf(cmd, "createrawtransaction \"[{\\\"txid\\\":\\\"%s\\\",\\\"vout\\\":%d}]\" \"{\\\"%s\\\":%s}\"\n", sTxid.c_str(), this->vout, ui->toAddressLineEdit->text().toLatin1().data(), amount);
    DoCommand doCreateTransaction(cmd);
    transactionHex = doCreateTransaction.getReturnFromStdOutPut();
    return transactionHex;
}

std::string MultiSignPage::importPrivKey(std::string _pubAddress)
{
    char cmd[512]={0};
    std::string privKey;
    sprintf(cmd, "dumpprivkey %s", _pubAddress.c_str());
    DoCommand doCreateImportPrivKey(cmd);
    privKey = doCreateImportPrivKey.getReturnFromStdOutPut();
    return privKey;
}
std::string MultiSignPage::signRawTransaction(std::string _hex, std::string _sTxid, int vout, std::string _scriptPubKey, std::string _redeemScript, std::string _privKey)
{
    char cmd[6000]={0};
    std::string signRawTransactionHex;
    sprintf(cmd, "signrawtransaction %s \"[{\\\"txid\\\":\\\"%s\\\",\\\"vout\\\":%d,\\\"scriptPubKey\\\":\\\"%s\\\",\\\"redeemScript\\\":\\\"%s\\\"}]\" \"[\\\"%s\\\"]\"\n", _hex.c_str(), _sTxid.c_str(), vout, _scriptPubKey.c_str(), _redeemScript.c_str(), _privKey.c_str());
    DoCommand doCreateImportPrivKey(cmd);
    signRawTransactionHex = doCreateImportPrivKey.getReturnFromStdOutPut();
    return signRawTransactionHex;
}
int MultiSignPage::broadcast(std::string rawTransaction)
{
    char cmd[6000]={0};
    sprintf(cmd, "sendrawtransaction %s", rawTransaction.c_str());
    DoCommand doBroadcast(cmd);
    doBroadcast.getReturnFromStdOutPut();
    ui->importLineEdit->clear();
    ui->satAddressLineEdit->clear();
    ui->thirdAddressLineEdIt->clear();
    ui->multisigAddressLineEdit->clear();
    ui->fromAddressLineEdit->clear();
    ui->toAddressLineEdit->clear();
    ui->amountLineEdit->clear();
    ui->dataTextEdit->clear();
    return 0;
}
void MultiSignPage::on_broadcastButton_clicked()
{
    if(ui->rawHexTextEdit->toPlainText().isEmpty())    return;
    if(broadcast(ui->rawHexTextEdit->toPlainText().toStdString()) !=0) return;
}

bool MultiSignPage::on_packetData()
{
    if(firstSigHex.isEmpty()||(sTxid.empty())||scriptPubKeyHex.empty()||redeemScript.empty()||(vout==-1)){
        return false;
    }
    uchar ucData[2048]={0};
    SPC_SEND_DATA_T spcSendData;
    QByteArray tmpByteArray = this->firstSigHex.toLatin1();
    spcSendData.pcTransaction = (uchar *)(tmpByteArray.data());
    spcSendData.ucTxidArrayNum = 1;
    const char *tmpTxid = this->sTxid.c_str();
    spcSendData.pcTxid[0] = (uchar *)(tmpTxid);
    spcSendData.ucVout[0] = this->vout;
    const char *tmpScriptPubKey = this->scriptPubKeyHex.c_str();
    spcSendData.pcScriptPubKey[0] = (uchar *)(tmpScriptPubKey);
    const char *tmpRedeemScript = this->redeemScript.c_str();
    spcSendData.pcRedeemScript[0] = (uchar *)(tmpRedeemScript);
    spcSendData.uiPrivKeyIndex = this->index;
    spcPacketSendData (ucData, &spcSendData);
    QFile f(QDir::homePath().append("/spcdata.bin"));
    if (!f.open(QIODevice::WriteOnly)){
        return false;
    }
    f.write((const char *)ucData,500);
    f.flush();
    f.close();
    return true;
}
//*******************************************************************************************************************

DoCommand::DoCommand(char _cCmd[])
{
    if(_cCmd == NULL) return;
    this->cCmd = new char [strlen(_cCmd)+4];
    strncpy(cCmd, _cCmd, (strlen(_cCmd)+4));
}
DoCommand::~DoCommand()
{
    if(cCmd){
        delete [] cCmd;
    }
}
int DoCommand::run()
{
}
std::string DoCommand::getReturnFromStdOutPut()
{
    std::string result;
    const std::string cmd(cCmd);
    RPCConsole::RPCExecuteCommandLine(result, cmd);
    return result;
}
