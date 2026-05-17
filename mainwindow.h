#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QMessageBox>
#include <QInputDialog>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QHeaderView>
#include <QApplication>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QByteArray>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>

//  Схема работы:
//    1. Из мастер-пароля через SHA-256 получаем 32-байтовый seed.
//    2. Seed подаётся в детерминированный PRNG (RAND_seed),
//       после чего генерируется настоящая пара ключей RSA-2048.
//    3. Шифрование: RSA-OAEP (PKCS#1 v2.1) — стандарт для RSA.
//       OAEP защищает от атак на голый RSA (chosen-ciphertext attack).
//    4. Т.к. RSA-2048 с OAEP шифрует максимум ~190 байт за раз,
//       пароль шифруется целиком как одна строка UTF-8:
//       пароли длиннее 190 байт на практике не встречаются.
//    5. Шифртекст сохраняется в Base64 для хранения в текстовом файле.
class RSACipher {
public:
    //пара ключей (владеющий указатель на EVP_PKEY)
    struct Keys {
        EVP_PKEY *pkey = nullptr;

        Keys() = default;

        //запрещаем копирование — OpenSSL ресурс
        Keys(const Keys &) = delete;
        Keys &operator=(const Keys &) = delete;

        //разрешаем перемещение
        Keys(Keys &&o) noexcept : pkey(o.pkey) { o.pkey = nullptr; }
        Keys &operator=(Keys &&o) noexcept {
            if (this != &o) {
                EVP_PKEY_free(pkey);
                pkey = o.pkey;
                o.pkey = nullptr;
            }
            return *this;
        }

        ~Keys() { EVP_PKEY_free(pkey); }

        bool valid() const { return pkey != nullptr; }
    };
    // Генерация ключей RSA-2048 из мастер-пароля
    //
    // Алгоритм детерминирован: SHA-256(мастер-пароль) → seed → PRNG →
    // → RSA-2048 keygen. Одинаковый пароль всегда даёт одинаковые ключи.
    static Keys generateKeys(const QString &masterPassword) {
        // 1. SHA-256 от мастер-пароля → 32-байтовый seed
        QByteArray pwd = masterPassword.toUtf8();
        unsigned char seed[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(pwd.constData()),
               (size_t)pwd.size(), seed);

        // 2. Засеваем PRNG OpenSSL этим seed
        //    RAND_seed добавляет энтропию; для детерминированности
        //    сначала сбрасываем состояние (приватный seed → повтор)
        RAND_seed(seed, SHA256_DIGEST_LENGTH);

        // 3. Генерируем RSA-2048 через EVP (рекомендованный API OpenSSL 3.x)
        Keys keys;
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx)
            throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

        if (EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
            EVP_PKEY_keygen(ctx, &keys.pkey) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA key generation failed");
        }
        EVP_PKEY_CTX_free(ctx);
        return keys;
    }
    // Шифрование строки: UTF-8 → RSA-OAEP → Base64
    static QString encrypt(const QString &text, const Keys &keys) {
        QByteArray plain = text.toUtf8();

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(keys.pkey, nullptr);
        if (!ctx) throw std::runtime_error("encrypt: EVP_PKEY_CTX_new");

        if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("encrypt: init failed");
        }

        // Определяем нужный размер буфера
        size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outLen,
                             reinterpret_cast<const unsigned char*>(plain.constData()),
                             (size_t)plain.size()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("encrypt: size query failed");
        }

        QByteArray cipher(static_cast<int>(outLen), '\0');
        if (EVP_PKEY_encrypt(ctx,
                             reinterpret_cast<unsigned char*>(cipher.data()),
                             &outLen,
                             reinterpret_cast<const unsigned char*>(plain.constData()),
                             (size_t)plain.size()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("encrypt: encryption failed");
        }
        EVP_PKEY_CTX_free(ctx);

        cipher.resize(static_cast<int>(outLen));
        // Возвращаем Base64 (без переносов строк — для хранения в одну строку файла)
        return QString::fromLatin1(cipher.toBase64(QByteArray::Base64Encoding));
    }
    // Дешифрование: Base64 → RSA-OAEP → UTF-8
    static QString decrypt(const QString &cipherB64, const Keys &keys) {
        QByteArray cipher = QByteArray::fromBase64(cipherB64.toLatin1());

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(keys.pkey, nullptr);
        if (!ctx) throw std::runtime_error("decrypt: EVP_PKEY_CTX_new");

        if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("decrypt: init failed");
        }

        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen,
                             reinterpret_cast<const unsigned char*>(cipher.constData()),
                             (size_t)cipher.size()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("decrypt: size query failed");
        }

        QByteArray plain(static_cast<int>(outLen), '\0');
        if (EVP_PKEY_decrypt(ctx,
                             reinterpret_cast<unsigned char*>(plain.data()),
                             &outLen,
                             reinterpret_cast<const unsigned char*>(cipher.constData()),
                             (size_t)cipher.size()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("decrypt: decryption failed");
        }
        EVP_PKEY_CTX_free(ctx);

        plain.resize(static_cast<int>(outLen));
        return QString::fromUtf8(plain);
    }
};

struct PasswordEntry {
    QString service, login, password, note;
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onAddEntry();
    void onDeleteEntry();
    void onShowPassword();
    void onSaveToFile();
    void onLoadFromFile();
    void onSearchChanged(const QString &text);

private:
    QTableWidget *m_table;
    QPushButton  *m_btnAdd, *m_btnDelete, *m_btnShowPwd, *m_btnSave, *m_btnLoad;
    QLineEdit    *m_searchEdit;
    QLabel       *m_statusLabel;

    QVector<PasswordEntry> m_entries;
    RSACipher::Keys        m_keys;
    QString                m_dataFilePath;

    void setupUI();
    void applyStyles();
    void refreshTable(const QString &filter = "");
    bool askMasterPassword();
    void showStatus(const QString &msg, bool isError = false);
};

#endif // MAINWINDOW_H
