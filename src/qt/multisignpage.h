#ifndef MULTISIGNPAGE_H
#define MULTISIGNPAGE_H

#include <QDialog>
#include <QPushButton>
#include "walletmodel.h"

#include<QByteArray>
#include<QString>


#define ATTACHMENTFILEPAT "mg"
#define SATELLITEEMAIL "service@spacechain.com"

class ClientModel;
class PlatformStyle;
using namespace std;

namespace Ui {
class MultiSignPage;
}

class MultiSignPage : public QDialog
{
    Q_OBJECT

public:
    explicit MultiSignPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    MultiSignPage(QWidget *parent = 0);
    ~MultiSignPage();

    void setClientModel(ClientModel *clientModel);
    void setModel(WalletModel *model);

public Q_SLOTS:

Q_SIGNALS:
    void packetData();

private Q_SLOTS:
    void on_generateButton_clicked();

    void on_emailButton_clicked();

    void on_signButton_clicked();

    void on_broadcastButton_clicked();

    bool on_packetData();

private:
    char *cTxid;
    std::string sTxid;
    int vout;
    Ui::MultiSignPage *ui;
    void init();
    QPushButton *testPushButton;

    std::string multisigAddress;

    std::string privKey;
    std::string scriptPubKeyHex;
    std::string redeemScript;
    QString firstSigHex;

    std::string createRawTransaction();
    std::string importPrivKey(std::string _pubAddress);
    std::string signRawTransaction(std::string , std::string, int, std::string, std::string, std::string);
    int broadcast(std::string);
    void getNeedRroadcastInfo(QString &);
    //privKey index
    int index;
    QString server;
    QString account;
    QString passwd;
};

class DoCommand
{
public:
    DoCommand(char _cCmd[]);
    ~DoCommand();
    int run();
    std::string getReturnFromStdOutPut();
private:
    //char cCmd[512];
    char *cCmd;
};

typedef struct spc_send_data {
    uchar   *pcTransaction;
    uchar   ucTxidArrayNum;
    uchar   *pcTxid[5];
    uchar   ucVout[5];
    uchar   *pcScriptPubKey[5];
    uchar   *pcRedeemScript[5];
    uint16_t  uiPrivKeyIndex;
} SPC_SEND_DATA_T;

#endif // MULTISIGNPAGE_H
