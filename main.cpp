#include <QApplication>
#include <QTimer>
#include "mainwindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("Журнал паролей");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("KubGU");

    MainWindow window;
    window.show();

    return app.exec();
}
