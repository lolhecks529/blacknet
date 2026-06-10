#ifndef GUI_H
#define GUI_H

#include <QWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QTimer>
#include <QTextEdit>
#include <QProgressBar>
#include <QPainter>
#include <QList>
#include <QSettings>
#include <QTableWidget>
#include <QHeaderView>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QSpinBox>
#include "AttackEngine.h"
#include "ProxyManager.h"
#include "BotManager.h"

class ChartWidget : public QWidget {
public:
    explicit ChartWidget(QWidget* parent = nullptr);
    void add_point(double bps);
    void clear();

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    static const int MAX_POINTS = 80;
    QList<double> points;
    double max_value;
};

class GUI : public QWidget {
public:
    GUI(AttackEngine& engine, ProxyManager& proxy, BotManager& bot);
    ~GUI();

private:
    void toggle_attack();
    void refresh_stats();
    void save_preset();
    void load_preset();
    void resolve_target();
    void show_report();
    void refresh_bot_list();

private:
    void setup_ui();
    void apply_theme();
    void log(const QString& msg);
    void update_progress();
    long long parse_data_size_gui(const QString& text);
    void add_bot_dialog();
    void show_credits();

    AttackEngine& engine;
    ProxyManager& proxy;
    BotManager& bot;

    
    QComboBox* method_combo;
    QLineEdit* target_edit;
    QLineEdit* port_edit;
    QLineEdit* threads_edit;
    QLineEdit* rate_edit;
    QLineEdit* size_edit;
    QLineEdit* packets_edit;
    QLineEdit* data_edit;
    QLineEdit* duration_edit;
    QCheckBox* proxy_check;
    QCheckBox* rand_src_check;
    QCheckBox* rand_port_check;

    
    QPushButton* start_btn;
    QPushButton* stop_btn;

    
    QLabel* status_label;
    QLabel* packets_label;
    QLabel* bytes_label;
    QLabel* rate_label;
    QLabel* peak_label;
    QLabel* threads_label;
    QLabel* time_label;
    QLabel* proxy_label;

    
    QProgressBar* packet_progress;
    QProgressBar* data_progress;
    QLabel* packet_prog_label;
    QLabel* data_prog_label;

    
    ChartWidget* chart;

    
    QComboBox* preset_combo;
    QPushButton* save_preset_btn;
    QPushButton* load_preset_btn;
    QPushButton* delete_preset_btn;

    
    QLineEdit* multi_target_edit;
    QLabel* resolved_label;

    
    QCheckBox* use_botnet_check;
    QTableWidget* bot_table;
    QLabel* bot_stats_label;
    QPushButton* add_bot_btn;
    QPushButton* remove_bot_btn;
    QPushButton* save_bots_btn;
    QPushButton* load_bots_btn;

    
    QTextEdit* log_edit;
    QPushButton* report_btn;

    
    QTimer* stats_timer;
    QTimer* chart_timer;

    
    bool attacking;
    QStringList target_list;
    int current_target_idx;
    long long last_bytes;
    QStringList log_buffer;
};

#endif
