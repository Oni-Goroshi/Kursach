QT       += core gui widgets

CONFIG   += c++17

TARGET   = password_journal
TEMPLATE = app

SOURCES += \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    mainwindow.h

DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000

# ----------------------------------------------------------------
# OpenSSL — RSA-2048
# ----------------------------------------------------------------

win32 {
    OPENSSL_DIR = D:/OpenSSL-Win64
    INCLUDEPATH += $$OPENSSL_DIR/include
    LIBS        += -L$$OPENSSL_DIR/lib \
                   -lssl \
                   -lcrypto
}

unix:!macx {
    LIBS += -lssl -lcrypto
}

macx {
    # Intel Mac:
    OPENSSL_DIR = /usr/local/opt/openssl@3
    # Apple Silicon (раскомментируйте если M1/M2/M3):
    # OPENSSL_DIR = /opt/homebrew/opt/openssl@3
    INCLUDEPATH += $$OPENSSL_DIR/include
    LIBS        += -L$$OPENSSL_DIR/lib \
                   -lssl \
                   -lcrypto
}
