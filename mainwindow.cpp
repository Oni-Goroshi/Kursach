#include "mainwindow.h"
#include <QTimer>
#include <stdexcept>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_dataFilePath("passwords.dat")
{
    setWindowTitle("Журнал паролей — RSA-2048 (OpenSSL)");
    setMinimumSize(860, 580);
    if (!askMasterPassword()) {
        QTimer::singleShot(0, qApp, &QApplication::quit);
        return;
    }
    setupUI();
    applyStyles();
    onLoadFromFile();
}

MainWindow::~MainWindow() {}

bool MainWindow::askMasterPassword() {
    bool ok = false;
    QString pwd = QInputDialog::getText(
        this, "Мастер-пароль",
        "Введите мастер-пароль для доступа к журналу:",
        QLineEdit::Password, "", &ok);
    if (!ok || pwd.isEmpty()) {
        QMessageBox::warning(this, "Отмена",
            "Мастер-пароль не введён. Программа завершит работу.");
        return false;
    }
    try {
        m_keys = RSACipher::generateKeys(pwd);
    } catch (const std::exception &ex) {
        QMessageBox::critical(this, "Ошибка",
            QString("Не удалось создать ключи RSA:\n%1").arg(ex.what()));
        return false;
    }
    return true;
}

void MainWindow::setupUI() {
    QWidget *central = new QWidget(this);
    setCentralWidget(central);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(16, 16, 16, 12);

    QLabel *titleLabel = new QLabel("🔐  Защищённый журнал паролей  [RSA-2048 / OAEP]");
    titleLabel->setObjectName("titleLabel");
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);

    QHBoxLayout *searchLayout = new QHBoxLayout();
    m_searchEdit = new QLineEdit();
    m_searchEdit->setPlaceholderText("Поиск по сервису или логину...");
    m_searchEdit->setObjectName("searchEdit");
    searchLayout->addWidget(new QLabel("🔍"));
    searchLayout->addWidget(m_searchEdit);
    mainLayout->addLayout(searchLayout);

    m_table = new QTableWidget(0, 4);
    m_table->setObjectName("mainTable");
    m_table->setHorizontalHeaderLabels({"Сервис", "Логин", "Пароль", "Заметка"});
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    mainLayout->addWidget(m_table);

    QGroupBox *btnGroup = new QGroupBox("Управление");
    btnGroup->setObjectName("btnGroup");
    QHBoxLayout *btnLayout = new QHBoxLayout(btnGroup);

    m_btnAdd     = new QPushButton("➕  Добавить");
    m_btnDelete  = new QPushButton("🗑️  Удалить");
    m_btnShowPwd = new QPushButton("👁️  Показать пароль");
    m_btnSave    = new QPushButton("💾  Сохранить");
    m_btnLoad    = new QPushButton("📂  Загрузить");
    m_btnAdd->setObjectName("btnAdd");
    m_btnDelete->setObjectName("btnDelete");
    m_btnShowPwd->setObjectName("btnShowPwd");
    m_btnSave->setObjectName("btnSave");
    m_btnLoad->setObjectName("btnLoad");

    btnLayout->addWidget(m_btnAdd);
    btnLayout->addWidget(m_btnDelete);
    btnLayout->addWidget(m_btnShowPwd);
    btnLayout->addStretch();
    btnLayout->addWidget(m_btnSave);
    btnLayout->addWidget(m_btnLoad);
    mainLayout->addWidget(btnGroup);

    m_statusLabel = new QLabel("Готов к работе.");
    m_statusLabel->setObjectName("statusLabel");
    mainLayout->addWidget(m_statusLabel);

    connect(m_btnAdd,     &QPushButton::clicked, this, &MainWindow::onAddEntry);
    connect(m_btnDelete,  &QPushButton::clicked, this, &MainWindow::onDeleteEntry);
    connect(m_btnShowPwd, &QPushButton::clicked, this, &MainWindow::onShowPassword);
    connect(m_btnSave,    &QPushButton::clicked, this, &MainWindow::onSaveToFile);
    connect(m_btnLoad,    &QPushButton::clicked, this, &MainWindow::onLoadFromFile);
    connect(m_searchEdit, &QLineEdit::textChanged, this, &MainWindow::onSearchChanged);
}

void MainWindow::applyStyles() {
    setStyleSheet(R"(
        QMainWindow { background-color: #1e1e2e; }
        QWidget {
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: "Segoe UI", Arial, sans-serif;
            font-size: 13px;
        }
        QLabel#titleLabel {
            font-size: 18px; font-weight: bold;
            color: #89b4fa; padding: 8px;
        }
        QLineEdit#searchEdit {
            background-color: #313244;
            border: 1px solid #45475a;
            border-radius: 6px;
            padding: 6px 10px; color: #cdd6f4;
        }
        QLineEdit#searchEdit:focus { border-color: #89b4fa; }
        QTableWidget#mainTable {
            background-color: #181825;
            alternate-background-color: #1e1e2e;
            border: 1px solid #313244;
            border-radius: 6px;
            gridline-color: #313244;
        }
        QHeaderView::section {
            background-color: #313244; color: #89b4fa;
            font-weight: bold; padding: 6px;
            border: none; border-right: 1px solid #45475a;
        }
        QTableWidget::item:selected { background-color: #45475a; }
        QGroupBox#btnGroup {
            border: 1px solid #313244; border-radius: 6px;
            margin-top: 6px; padding: 8px;
            font-size: 12px; color: #6c7086;
        }
        QPushButton {
            border-radius: 6px; padding: 7px 14px;
            font-weight: bold; font-size: 12px; min-width: 100px;
        }
        QPushButton#btnAdd     { background-color: #60a5fa; color: #0f172a; }
        QPushButton#btnAdd:hover    { background-color: #3b82f6; }
        QPushButton#btnDelete  { background-color: #93c5fd; color: #0f172a; }
        QPushButton#btnDelete:hover { background-color: #60a5fa; }
        QPushButton#btnShowPwd { background-color: #bfdbfe; color: #0f172a; }
        QPushButton#btnShowPwd:hover{ background-color: #93c5fd; }
        QPushButton#btnSave    { background-color: #2563eb; color: #f8fafc; }
        QPushButton#btnSave:hover   { background-color: #1d4ed8; }
        QPushButton#btnLoad    { background-color: #1e40af; color: #f8fafc; }
        QPushButton#btnLoad:hover   { background-color: #1e3a8a; }
        QLabel#statusLabel { color: #6c7086; font-size: 11px; padding: 2px 4px; }
        QScrollBar:vertical { background: #1e1e2e; width: 10px; }
        QScrollBar::handle:vertical { background: #45475a; border-radius: 5px; }
    )");
}

void MainWindow::onAddEntry() {
    bool ok;
    QString service = QInputDialog::getText(this, "Добавить запись",
        "Название сервиса:", QLineEdit::Normal, "", &ok);
    if (!ok || service.trimmed().isEmpty()) return;

    QString login = QInputDialog::getText(this, "Добавить запись",
        "Логин / E-mail:", QLineEdit::Normal, "", &ok);
    if (!ok) return;

    QString password = QInputDialog::getText(this, "Добавить запись",
        "Пароль:", QLineEdit::Password, "", &ok);
    if (!ok || password.isEmpty()) return;

    QString note = QInputDialog::getText(this, "Добавить запись",
        "Заметка (необязательно):", QLineEdit::Normal, "", &ok);
    if (!ok) note = "";

    PasswordEntry entry;
    entry.service = service.trimmed();
    entry.login   = login.trimmed();
    entry.note    = note.trimmed();
    try {
        entry.password = RSACipher::encrypt(password, m_keys);
    } catch (const std::exception &ex) {
        showStatus(QString("❌ Ошибка шифрования: %1").arg(ex.what()), true);
        return;
    }
    m_entries.append(entry);
    refreshTable(m_searchEdit->text());
    showStatus(QString("✅ Запись для '%1' добавлена.").arg(entry.service));
}

void MainWindow::onDeleteEntry() {
    int row = m_table->currentRow();
    if (row < 0) { showStatus("⚠️ Выберите запись для удаления.", true); return; }
    QString service = m_table->item(row, 0)->text();
    QString login   = m_table->item(row, 1)->text();
    if (QMessageBox::question(this, "Подтверждение",
            QString("Удалить запись для '%1'?").arg(service),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    for (int i = 0; i < m_entries.size(); i++) {
        if (m_entries[i].service == service && m_entries[i].login == login) {
            m_entries.remove(i); break;
        }
    }
    refreshTable(m_searchEdit->text());
    showStatus(QString("🗑️ Запись для '%1' удалена.").arg(service));
}

void MainWindow::onShowPassword() {
    int row = m_table->currentRow();
    if (row < 0) { showStatus("⚠️ Выберите запись.", true); return; }
    QString service = m_table->item(row, 0)->text();
    QString login   = m_table->item(row, 1)->text();
    for (const PasswordEntry &entry : m_entries) {
        if (entry.service == service && entry.login == login) {
            try {
                QString plain = RSACipher::decrypt(entry.password, m_keys);
                QMessageBox::information(this, "Пароль",
                    QString("Сервис: %1\nЛогин:  %2\nПароль: %3")
                        .arg(entry.service, entry.login, plain));
                showStatus(QString("👁️ Пароль для '%1' показан.").arg(service));
            } catch (const std::exception &ex) {
                showStatus(QString("❌ Ошибка дешифрования — проверьте мастер-пароль. (%1)")
                           .arg(ex.what()), true);
            }
            return;
        }
    }
}

void MainWindow::onSaveToFile() {
    QFile file(m_dataFilePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        showStatus("❌ Не удалось открыть файл для записи.", true); return;
    }
    QTextStream out(&file);
    out.setEncoding(QStringConverter::Utf8);
    out << "# Password Journal — RSA-2048/OAEP (OpenSSL)\n";
    out << "# Saved: "
        << QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") << "\n";
    for (const PasswordEntry &e : m_entries)
        out << e.service << "|" << e.login << "|"
            << e.password << "|" << e.note << "\n";
    file.close();
    showStatus(QString("💾 Сохранено %1 записей в '%2'.")
               .arg(m_entries.size()).arg(m_dataFilePath));
}

void MainWindow::onLoadFromFile() {
    QFile file(m_dataFilePath);
    if (!file.exists()) {
        showStatus("📂 Файл данных не найден — начинаем с чистого листа."); return;
    }
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        showStatus("❌ Не удалось открыть файл.", true); return;
    }
    m_entries.clear();
    QTextStream in(&file);
    in.setEncoding(QStringConverter::Utf8);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        int p1 = line.indexOf('|'), p2 = line.indexOf('|', p1+1),
            p3 = line.indexOf('|', p2+1);
        if (p1 < 0 || p2 < 0 || p3 < 0) continue;
        PasswordEntry e;
        e.service  = line.mid(0, p1);
        e.login    = line.mid(p1+1, p2-p1-1);
        e.password = line.mid(p2+1, p3-p2-1);
        e.note     = line.mid(p3+1);
        m_entries.append(e);
    }
    file.close();
    refreshTable();
    showStatus(QString("📂 Загружено %1 записей.").arg(m_entries.size()));
}

void MainWindow::onSearchChanged(const QString &text) { refreshTable(text); }

void MainWindow::refreshTable(const QString &filter) {
    m_table->setRowCount(0);
    for (const PasswordEntry &e : m_entries) {
        if (!filter.isEmpty()
            && !e.service.contains(filter, Qt::CaseInsensitive)
            && !e.login.contains(filter, Qt::CaseInsensitive)) continue;
        int row = m_table->rowCount();
        m_table->insertRow(row);
        m_table->setItem(row, 0, new QTableWidgetItem(e.service));
        m_table->setItem(row, 1, new QTableWidgetItem(e.login));
        m_table->setItem(row, 2, new QTableWidgetItem("••••••••"));
        m_table->setItem(row, 3, new QTableWidgetItem(e.note));
    }
}

void MainWindow::showStatus(const QString &msg, bool isError) {
    m_statusLabel->setText(msg);
    m_statusLabel->setStyleSheet(isError
        ? "color: #f38ba8; font-size: 11px;"
        : "color: #a6e3a1; font-size: 11px;");
}
