#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "pcapreader.h"
#include "streamanalyzer.h"

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

/// @brief Main window: browse a `.pcap` file, pick a UDP flow, and inspect its RTP stream.
///
/// Flow: double-clicking a `.pcap` file in the file tree opens it via
/// PcapReader and lists its UDP flows; double-clicking a flow parses it via
/// StreamAnalyzer and lists the SSRCs found; double-clicking (or analysing)
/// an SSRC shows its sequence-number statistics.
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

    /// @brief Handles a double-click in the `.pcap` file tree; opens the selected file.
    void fileview_doubleClicked(const QModelIndex& index);

    /// @brief Handles a double-click on a UDP flow row; parses it as RTP.
    void connection_doubleClicked(const QModelIndex& index);

    /// @brief Handles a double-click on an SSRC entry; shows its sequence statistics.
    void ssrc_doubleClicked(const QModelIndex& index);

    /// @brief Reconstructs the Flow_Endpoints for the flow-table row at @p index.
    Flow_Endpoints find_selected_connection(const QModelIndex& index);

    /// @brief Opens m_selected_file via PcapReader and lists its UDP flows.
    void display_pcap();

    /// @brief Lists the SSRCs found for @p ep after StreamAnalyzer has parsed it.
    void display_parsed_rtp_streams(Flow_Endpoints ep);

    /// @brief Shows sequence-number statistics for @p ssrc.
    void display_analyzed_stream(uint32_t ssrc);

private slots:
    void on_btn_analyse_clicked();
    void on_btn_reset_clicked();
    void on_btn_decypher_clicked();
    void on_btn_exit_clicked();
    void on_btn_clear_clicked();
    void on_rb_enable_offset_toggled();
};

#endif // MAINWINDOW_H
