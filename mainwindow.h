#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "pcapreader.h"
#include "streamanalyzer.h"

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QString m_selected_file;
    std::unique_ptr<PcapReader> m_pcap_reader;
    std::unique_ptr<StreamAnalyzer> m_stream_analyzer;

    void fileview_doubleClicked(const QModelIndex& index);
    void connection_doubleClicked(const QModelIndex& index);
    void ssrc_doubleClicked(const QModelIndex& index);
    Flow_Endpoints find_selected_connection(const QModelIndex& index);

    void display_parsed_rtp_streams();
    void display_pcap();
    void display_analyzed_stream(uint32_t ssrc);

private slots:
    void on_btn_analyse_clicked();
    void on_btn_reset_clicked();
    void on_btn_decypher_clicked();
    void on_btn_exit_clicked();
    void on_btn_clear_clicked();
};

#endif // MAINWINDOW_H
