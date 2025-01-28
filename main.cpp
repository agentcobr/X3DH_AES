#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include <iostream>

#include <QByteArray>
#include <QFile>
#include <QDebug>
#include <stdexcept>
#include <QTextStream>
#include <QString>
#include <QCryptographicHash>
#include <vector>

using json = nlohmann::json;

struct KeyPair {
    QByteArray privateKey;
    QByteArray publicKey;
};

struct KeyStorage {
    KeyPair IK;
    KeyPair EK;
    KeyPair SPK;
    KeyPair OPK;
};

class Function {
public:
    KeyPair generateKeyPairX25519();
    KeyPair generateKeyPairED25519();

    KeyPair generateIK();
    KeyPair generateEK();
    KeyPair generateSPK();
    KeyPair generateOPK();
    KeyPair generateK();

    void generateAndStoreOPKs(int count);
    const std::vector<KeyPair>& getOTPs() const { return OTPs; }
    QByteArray getOPKPublicKey();
    void removeUsedOPK();

    std::string serializePublicKey(const QByteArray& publicKey);
    std::string serializePrivateKey(const QByteArray& privateKey);

    KeyPair generate_SPK(const QByteArray& IK_privateKey);
    QByteArray signData(const QByteArray& data, const QByteArray& privateKey);
    bool verifySignature(const QByteArray& data, const QByteArray& signature, const QByteArray& publicKey);

    static std::string toBase64(const QByteArray& data);
    static QByteArray fromBase64(const std::string& data);

    //------DH-----
    QByteArray computeSharedSecret(const KeyPair& localKey, const QByteArray& remotePublicKey);

    //------X3DH-----
    QByteArray X3DH(const KeyPair& localIK, const KeyPair& localEK,
                    const QByteArray& remoteIKPublic, const QByteArray& remoteSPKPublic,
                    const std::vector<KeyPair>& remoteOPKs, int opkIndex);

    //------X3DH with signKey------
    QByteArray X3DH_true(const KeyPair& localIK, const KeyPair& localEK,
                         const QByteArray& remoteIKPublic, const QByteArray& remoteSPKPublic,
                         const std::vector<KeyPair>& remoteOPKs, int opkIndex,
                         const KeyPair& KeySign, const QByteArray& dataKeySign);


private:
    QByteArray IK_private;
    QByteArray IK_public;
    KeyPair signedPreKey;
    std::vector<KeyPair> OTPs;

    QByteArray extractPrivateKey(EVP_PKEY* pkey);
    QByteArray extractPublicKey(EVP_PKEY* pkey);
};

std::string Function::toBase64(const QByteArray& data) {
    return data.toBase64().toStdString();
}

QByteArray Function::fromBase64(const std::string& data) {
    return QByteArray::fromBase64(data.c_str());
}

KeyPair Function::generateKeyPairX25519() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Key generation failed.");
    }

    BIO* bioPrivate = BIO_new(BIO_s_mem());
    if (!bioPrivate) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIO for private key");
    }

    if (!PEM_write_bio_PrivateKey(bioPrivate, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bioPrivate);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to write private key to BIO");
    }

    BUF_MEM* bufferPrivate;
    BIO_get_mem_ptr(bioPrivate, &bufferPrivate);
    QByteArray privateKey(bufferPrivate->data, bufferPrivate->length);
    BIO_free(bioPrivate);

    BIO* bioPublic = BIO_new(BIO_s_mem());
    if (!bioPublic) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIO for public key");
    }

    if (!PEM_write_bio_PUBKEY(bioPublic, pkey)) {
        BIO_free(bioPublic);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to write public key to BIO");
    }

    BUF_MEM* bufferPublic;
    BIO_get_mem_ptr(bioPublic, &bufferPublic);
    QByteArray publicKey(bufferPublic->data, bufferPublic->length);
    BIO_free(bioPublic);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return KeyPair{privateKey, publicKey};
}

KeyPair Function::generateKeyPairED25519() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Key generation failed.");
    }

    BIO* bioPrivate = BIO_new(BIO_s_mem());
    if (!bioPrivate) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIO for private key");
    }

    if (!PEM_write_bio_PrivateKey(bioPrivate, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bioPrivate);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to write private key to BIO");
    }

    BUF_MEM* bufferPrivate;
    BIO_get_mem_ptr(bioPrivate, &bufferPrivate);
    QByteArray privateKey(bufferPrivate->data, bufferPrivate->length);
    BIO_free(bioPrivate);

    BIO* bioPublic = BIO_new(BIO_s_mem());
    if (!bioPublic) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIO for public key");
    }

    if (!PEM_write_bio_PUBKEY(bioPublic, pkey)) {
        BIO_free(bioPublic);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to write public key to BIO");
    }

    BUF_MEM* bufferPublic;
    BIO_get_mem_ptr(bioPublic, &bufferPublic);
    QByteArray publicKey(bufferPublic->data, bufferPublic->length);
    BIO_free(bioPublic);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return KeyPair{privateKey, publicKey};
}

KeyPair Function::generateIK() {
    return generateKeyPairX25519();
}

KeyPair Function::generateEK() {
    return generateKeyPairX25519();
}

KeyPair Function::generateSPK() {
    return generateKeyPairX25519();
}

KeyPair Function::generateOPK() {
    return generateKeyPairX25519();
}

void Function::generateAndStoreOPKs(int count) {
    for (int i = 0; i < count; ++i) {
        KeyPair opk = generateOPK();
        OTPs.push_back(opk);
    }
}

QByteArray Function::getOPKPublicKey() {
    if (OTPs.empty()) {
        throw std::runtime_error("No OPKs available");
    }
    return OTPs.front().publicKey;
}

void Function::removeUsedOPK() {
    if (!OTPs.empty()) {
        OTPs.erase(OTPs.begin());
    }
}

KeyPair Function::generateK() {
    return generateKeyPairED25519();
}

std::string Function::serializePublicKey(const QByteArray& publicKey) {
    BIO* bio = BIO_new_mem_buf(publicKey.data(), publicKey.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for public key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        throw std::runtime_error("Failed to read public key");
    }

    bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write public key to BIO");
    }

    char* data = nullptr;
    size_t len = BIO_get_mem_data(bio, &data);
    std::string pemPublicKey(data, len);

    BIO_free(bio);
    EVP_PKEY_free(pkey);

    return pemPublicKey;
}

std::string Function::serializePrivateKey(const QByteArray& privateKey) {
    BIO* bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        throw std::runtime_error("Failed to read private key");
    }

    bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write private key to BIO");
    }

    char* data = nullptr;
    size_t len = BIO_get_mem_data(bio, &data);
    std::string pemPrivateKey(data, len);

    BIO_free(bio);
    EVP_PKEY_free(pkey);

    return pemPrivateKey;
}

QByteArray Function::signData(const QByteArray& data, const QByteArray& privateKey) {
    BIO* bioPrivate = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    if (!bioPrivate) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bioPrivate, nullptr, nullptr, nullptr);
    BIO_free(bioPrivate);
    if (!pkey) {
        throw std::runtime_error("Failed to read private key");
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Private key is not an ED25519 key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize signing");
    }

    size_t siglen;
    if (EVP_DigestSign(ctx, nullptr, &siglen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to determine signature length");
    }

    QByteArray signature(siglen, 0);
    if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(signature.data()), &siglen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to sign data");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return signature;
}

bool Function::verifySignature(const QByteArray& data, const QByteArray& signature, const QByteArray& publicKey) {
    BIO* bioPublic = BIO_new_mem_buf(publicKey.data(), publicKey.size());
    if (!bioPublic) {
        throw std::runtime_error("Failed to create BIO for public key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bioPublic, nullptr, nullptr, nullptr);
    BIO_free(bioPublic);
    if (!pkey) {
        throw std::runtime_error("Failed to read public key");
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Public key is not an ED25519 key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize verification");
    }

    int result = EVP_DigestVerify(
        ctx,
        reinterpret_cast<const unsigned char*>(signature.data()),
        signature.size(),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size()
        );

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result == 1;
}

QByteArray Function::computeSharedSecret(const KeyPair& localKey, const QByteArray& remotePublicKey) {
    std::unique_ptr<BIO, decltype(&BIO_free)> privBio(
        BIO_new_mem_buf(localKey.privateKey.data(), localKey.privateKey.size()), BIO_free);
    if (!privBio) {
        throw std::runtime_error("Failed to create BIO for private key.");
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> privKey(
        PEM_read_bio_PrivateKey(privBio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!privKey) {
        unsigned long err = ERR_get_error();
        char errBuff[120];
        ERR_error_string_n(err, errBuff, sizeof(errBuff));
        throw std::runtime_error(std::string("Failed to read private key: ") + errBuff);
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> pubBio(
        BIO_new_mem_buf(remotePublicKey.data(), remotePublicKey.size()), BIO_free);
    if (!pubBio) {
        throw std::runtime_error("Failed to create BIO for public key.");
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pubKey(
        PEM_read_bio_PUBKEY(pubBio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!pubKey) {
        unsigned long err = ERR_get_error();
        char errBuff[120];
        ERR_error_string_n(err, errBuff, sizeof(errBuff));
        throw std::runtime_error(std::string("Failed to read public key: ") + errBuff);
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(privKey.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to create context for shared secret computation.");
    }

    if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize context for shared secret computation.");
    }

    if (EVP_PKEY_derive_set_peer(ctx.get(), pubKey.get()) <= 0) {
        throw std::runtime_error("Failed to set peer key for shared secret computation.");
    }

    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secretLen) <= 0) {
        throw std::runtime_error("Failed to determine shared secret length.");
    }

    QByteArray sharedSecret(secretLen, 0);
    if (EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char*>(sharedSecret.data()), &secretLen) <= 0) {
        throw std::runtime_error("Failed to derive shared secret.");
    }

    return sharedSecret;
}

//-----------------------X3DH without signature key------------------
QByteArray Function::X3DH(const KeyPair& localIK, const KeyPair& localEK,
                          const QByteArray& remoteIKPublic, const QByteArray& remoteSPKPublic,
                          const std::vector<KeyPair>& remoteOPKs, int opkIndex) {
    if (opkIndex < 0 || static_cast<size_t>(opkIndex) >= remoteOPKs.size()) {
        throw std::out_of_range("Invalid OPK index");
    }

    QByteArray DH1 = computeSharedSecret(localIK, remoteSPKPublic);
    qDebug() << "DH1: " << DH1.toHex();

    QByteArray DH2 = computeSharedSecret(localEK, remoteIKPublic);
    qDebug() << "DH2: " << DH2.toHex();

    QByteArray DH3 = computeSharedSecret(localEK, remoteSPKPublic);
    qDebug() << "DH3: " << DH3.toHex();

    QByteArray DH4 = computeSharedSecret(localEK, remoteOPKs[opkIndex].publicKey);
    qDebug() << "DH4: " << DH4.toHex();

    QByteArray sharedSecret = DH1 + DH2 + DH3 + DH4;

    QByteArray finalKey = QCryptographicHash::hash(sharedSecret, QCryptographicHash::Sha256);
    qDebug() << "Secret X3DH: " << finalKey.toHex();

    return finalKey;
}

//---------------------X3DH with signature key----------------
QByteArray Function::X3DH_true(const KeyPair& localIK, const KeyPair& localEK,
                               const QByteArray& remoteIKPublic, const QByteArray& remoteSPKPublic,
                               const std::vector<KeyPair>& remoteOPKs, int opkIndex,
                               const KeyPair& KeySign, const QByteArray& dataKeySign) {
    Function func;

    if (!func.verifySignature(remoteSPKPublic, dataKeySign, KeySign.publicKey)) {
        qDebug() << "Errror";
        throw std::runtime_error("Signature verification failed!");
    } else {
        qDebug() << "SignKey is a valid";
    }

    if (opkIndex < 0 || static_cast<size_t>(opkIndex) >= remoteOPKs.size()) {
        throw std::out_of_range("Invalid OPK index");
    }

    QByteArray DH1 = func.computeSharedSecret(localIK, remoteSPKPublic);
    qDebug() << "DH1: " << DH1.toHex();

    QByteArray DH2 = func.computeSharedSecret(localEK, remoteIKPublic);
    qDebug() << "DH2: " << DH2.toHex();

    QByteArray DH3 = func.computeSharedSecret(localEK, remoteSPKPublic);
    qDebug() << "DH3: " << DH3.toHex();

    QByteArray DH4 = func.computeSharedSecret(localEK, remoteOPKs[opkIndex].publicKey);
    qDebug() << "DH4: " << DH4.toHex();

    QByteArray sharedSecret = DH1 + DH2 + DH3 + DH4;

    QByteArray finalKey = QCryptographicHash::hash(sharedSecret, QCryptographicHash::Sha256);
    qDebug() << "Secret X3DH: " << finalKey.toHex();

    return finalKey;
}


//----------------------------AES---------------------
QByteArray encryptMessage(const QByteArray& message, const QByteArray& key, QByteArray& iv, QByteArray& tag) {
    const int ivSize = 12;
    iv = QByteArray(ivSize, 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), ivSize);

    QByteArray encryptedMessage(message.size(), 0);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    int len = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES-GCM");
    }

    EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()),
                       reinterpret_cast<const unsigned char*>(iv.data()));

    if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(encryptedMessage.data()), &len,
                               reinterpret_cast<const unsigned char*>(message.data()), message.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt message");
    }

    int ciphertextLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(encryptedMessage.data()) + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    ciphertextLen += len;

    tag = QByteArray(16, 0);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());

    EVP_CIPHER_CTX_free(ctx);

    encryptedMessage.resize(ciphertextLen);
    return encryptedMessage;
}

QByteArray decryptMessage(const QByteArray& encryptedMessage, const QByteArray& key, const QByteArray& iv, const QByteArray& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    QByteArray decryptedMessage(encryptedMessage.size(), 0);
    int len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES-GCM");
    }

    EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()),
                       reinterpret_cast<const unsigned char*>(iv.data()));

    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(decryptedMessage.data()), &len,
                               reinterpret_cast<const unsigned char*>(encryptedMessage.data()), encryptedMessage.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt message");
    }

    int plaintextLen = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<char*>(tag.data()));

    if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(decryptedMessage.data()) + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }

    plaintextLen += len;
    EVP_CIPHER_CTX_free(ctx);

    decryptedMessage.resize(plaintextLen);
    return decryptedMessage;
}


int main() {
    Function func;

    KeyPair IK = func.generateIK(); // X25519
    KeyPair EK = func.generateEK(); // X25519

    std::vector<KeyPair> OPKs;
    for (int i = 0; i < 2; ++i) {
        OPKs.push_back(func.generateOPK());
    }

    KeyPair ed25519Key = func.generateK(); // ED25519

    QByteArray data = "Hi =)";
    QByteArray signature = func.signData(data, ed25519Key.privateKey);
    qDebug() << "Hi =) ->" << signature.toHex();

    if (func.verifySignature(data, signature, ed25519Key.publicKey)) {
        qDebug() << "Valid data!!!";
    }

    KeyPair SPK = func.generateSPK();
    QByteArray signedSPK = func.signData(SPK.publicKey, ed25519Key.privateKey);
    qDebug() << "Signed SPK:" << signedSPK.toHex();

    if(func.verifySignature(SPK.publicKey, signedSPK, ed25519Key.publicKey)) {
        qDebug() << "Key valid!!!!";
    }

    std::string ikPublicKey = func.toBase64(func.serializePublicKey(IK.publicKey).c_str());
    std::string ekPublicKey = func.toBase64(func.serializePublicKey(EK.publicKey).c_str());
    std::string spkPublicKey = func.toBase64(func.serializePublicKey(SPK.publicKey).c_str());
    std::vector<std::string> opkPublicKeys;
    for (const auto& opk : OPKs) {
        opkPublicKeys.push_back(func.toBase64(func.serializePublicKey(opk.publicKey).c_str()));
    }

    std::string signSPKBase64 = func.toBase64(signedSPK);

    // Сбор данных для передачи
    json fullKeyAndSign = {
        {"IK", ikPublicKey},
        {"EK", ekPublicKey},
        {"SPK", spkPublicKey},
        {"OPK", opkPublicKeys},
        {"Sign SPK public key", signSPKBase64}
    };

    std::cout << fullKeyAndSign.dump(4) << std::endl;

    std::cerr << "----------------------------DH--------------------" << std::endl;

    // Генерация ключей
    KeyPair localKey = func.generateKeyPairX25519();
    KeyPair remoteKey = func.generateKeyPairX25519();

    try {
        QByteArray sharedSecret = func.computeSharedSecret(localKey, remoteKey.publicKey);
        qDebug() << "Shared secret:" << sharedSecret.toHex();
    } catch (const std::runtime_error& e) {
        qDebug() << "Error:" << e.what();
    }

    std::cerr << "-------------------------X3DH------------------------" << std::endl;

    Function allKey;
    KeyPair localIK = allKey.generateIK();
    KeyPair localEK = allKey.generateEK();

    KeyPair remoteIK = allKey.generateIK();
    KeyPair remoteSPK = allKey.generateSPK();
    std::vector<KeyPair> remoteOPKs;
    for(int i = 0; i <= 5; ++i) {
        remoteOPKs.push_back(allKey.generateOPK());
    }

    int opkIndex = 3;

    QByteArray sharedSecret = allKey.X3DH(localIK, localEK, remoteIK.publicKey, remoteSPK.publicKey, remoteOPKs, opkIndex);
    std::cout << std::endl;



    std::cerr << "-----------------------X3DH_AES------------------------" << std::endl;

    QByteArray key = sharedSecret;
    QByteArray iv, tag;
    QByteArray message = "Hello, world!!! It's work!";
    qDebug() << "Open a message: " << message;

    QByteArray encryptedMessage = encryptMessage(message, key, iv, tag);
    qDebug() << "Erypted Message:" << encryptedMessage.toHex();

    QByteArray decryptedMessage = decryptMessage(encryptedMessage, key, iv, tag);

    qDebug() << "Decrypted Message: " << decryptedMessage;

    std::cout << std::endl;


    std::cerr << "------------------------X3DH with sign key--------------" << std::endl;

    Function X3DH_KEY;
    KeyPair localIK_A = X3DH_KEY.generateIK();
    KeyPair localEK_A = X3DH_KEY.generateEK();

    KeyPair remoteIK_B = X3DH_KEY.generateIK();
    KeyPair remoteSPK_B = X3DH_KEY.generateSPK();
    KeyPair signKey = X3DH_KEY.generateK();
    QByteArray dataSignKey = X3DH_KEY.signData(remoteSPK_B.publicKey, signKey.privateKey);
    std::vector<KeyPair> remoteOPKs_B;
    for(int i = 0; i <= 5; ++i) {
        remoteOPKs_B.push_back(X3DH_KEY.generateOPK());
    }

    int opkIndex_B = 3;

    QByteArray endSharedSecret = X3DH_KEY.X3DH_true(localIK_A, localEK_A, remoteIK_B.publicKey,
                                                    remoteSPK_B.publicKey, remoteOPKs_B, opkIndex_B,
                                                    signKey, dataSignKey);

    return 0;
}



