#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "fileutils.h"

#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    FileUtils::initialize_fileview(ui->tw_filesystem);

    connect(ui->tw_filesystem, &QTreeView::doubleClicked, this, &MainWindow::fileview_doubleClicked);
    connect(ui->table_connections, &QTableWidget::doubleClicked, this, &MainWindow::connection_doubleClicked);
    connect(ui->table_rtp_in_connect, &QTableWidget::doubleClicked, this, &MainWindow::ssrc_doubleClicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

//Buttons:
void MainWindow::on_btn_analyse_clicked() {
    QList<QTableWidgetItem*> selected_items = ui->table_rtp_in_connect->selectedItems();
    if (selected_items.isEmpty()) {
        QMessageBox::warning(this, "No Stream selected", "You have to select a Stream befor you can analyze it.");
        return;
    }

    QString ssrc_text = selected_items.first()->text();
    uint32_t ssrc = static_cast<uint32_t>(ssrc_text.toUInt(nullptr,16));
    MainWindow::display_analyzed_stream(ssrc);
}

void MainWindow::on_btn_reset_clicked() {
    ui->table_rtp_in_connect->clear();
    ui->table_rtp_in_connect->setColumnCount(0);
    ui->table_rtp_in_connect->setRowCount(0);

    ui->tw_stream_results->clear();

}

void MainWindow::on_btn_decypher_clicked() {
    qDebug() << "btn Decypher";

}

void MainWindow::on_btn_exit_clicked() {
    qDebug() << "btn Exit";

}

void MainWindow::on_btn_clear_clicked() {
    qDebug() << "btn Clear";

}

//DoubleClick-Connects:
void MainWindow::fileview_doubleClicked(const QModelIndex& index) {
    if (!index.isValid()) return;

    QString file = FileUtils::get_filepath(ui->tw_filesystem, index);
    if (file.isEmpty()) {
        QMessageBox::warning(this, "Wrong Format", "Unsupported or unknown filetype. Only .pcap-files are currently supported");
        return;
    } else if (file.contains("dir")) {
        return;
    }

    m_selected_file = file;
    MainWindow::display_pcap();
}

void MainWindow::connection_doubleClicked(const QModelIndex& index) {
    if (!index.isValid()) return;

    Flow_Endpoints selected_ep = MainWindow::find_selected_connection(index);
    std::vector<PacketInfo> selected_stream = m_pcap_reader->get_stream(selected_ep);

    m_stream_analyzer = std::make_unique<StreamAnalyzer>(selected_stream);
    ui->table_rtp_in_connect->clearContents();
    MainWindow::display_parsed_rtp_streams();
}

void MainWindow::ssrc_doubleClicked(const QModelIndex& index) {
    if (!index.isValid()) return;

    uint32_t ssrc = static_cast<uint32_t>(
        ui->table_rtp_in_connect->item(index.row(), 0)->text().toUInt(nullptr,16)
        );
    MainWindow::display_analyzed_stream(ssrc);
}

//Display-Functions:
void MainWindow::display_pcap() {
    m_pcap_reader = std::make_unique<PcapReader>(m_selected_file);

    std::vector<Flow_Endpoints> endpoints = m_pcap_reader->get_flow_endpoints();
    ui->table_connections->setRowCount(endpoints.size());

    for (int row = 0; row < endpoints.size(); row++) {
        const Flow_Endpoints& row_data = endpoints[row];
        uint16_t pkt_count = m_pcap_reader->get_pkt_count(row_data.source_ip, row_data.source_port, row_data.destination_ip, row_data.destination_port);
        ui->table_connections->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(row_data.source_ip)));
        ui->table_connections->setItem(row, 1, new QTableWidgetItem(QString::number(row_data.source_port)));
        ui->table_connections->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(row_data.destination_ip)));
        ui->table_connections->setItem(row, 3, new QTableWidgetItem(QString::number(row_data.destination_port)));
        ui->table_connections->setItem(row, 5, new QTableWidgetItem(QString::number(pkt_count)));
    }
}

Flow_Endpoints MainWindow::find_selected_connection(const QModelIndex& index) {
    int row = index.row();
    return {
        ui->table_connections->item(row, 0)->text().toStdString(),
        ui->table_connections->item(row, 1)->text().toUShort(),
        ui->table_connections->item(row, 2)->text().toStdString(),
        ui->table_connections->item(row, 3)->text().toUShort()
    };
}

void MainWindow::display_parsed_rtp_streams() {
    QList<uint32_t> ssrc = m_stream_analyzer->get_ssrcs();

    ui->table_rtp_in_connect->setRowCount(ssrc.size());
    ui->table_rtp_in_connect->setColumnCount(2);
    ui->table_rtp_in_connect->setHorizontalHeaderLabels(QStringList({"SSRC", "Packets"}));

    for (int row = 0; row < ssrc.size(); row++) {
        QString hex_value = QString("%1").arg(ssrc[row], 8, 16, QLatin1Char('0')).toUpper();
        hex_value = "0x" + hex_value;
        ui->table_rtp_in_connect->setItem(row, 0, new QTableWidgetItem(hex_value));
        size_t count = m_stream_analyzer->get_rtp_per_ssrc(ssrc[row]);
        ui->table_rtp_in_connect->setItem(row, 1, new QTableWidgetItem(QString::number(count)));
    }
}

void MainWindow::display_analyzed_stream(uint32_t ssrc) {
    SequenceStat stream = m_stream_analyzer->analyse_sequence(ssrc);
    QString seq_break = stream.seq_break ? "Yes" : "No";

    QString hex_value = QString("%1").arg(ssrc, 8, 16, QLatin1Char('0')).toUpper();
    hex_value = "0x" + hex_value;

    QTreeWidgetItem* root = new QTreeWidgetItem(ui->tw_stream_results);
    root->setText(0, hex_value);

    QTreeWidgetItem* exp_pkt = new QTreeWidgetItem(root);
    exp_pkt->setText(0, "Expected Packets: " + QString::number(stream.expected_pkt));
    QTreeWidgetItem* act_pkt = new QTreeWidgetItem(root);
    act_pkt->setText(0, "Actual Items: " + QString::number(stream.actual_pkt));
    QTreeWidgetItem* seq_brk = new QTreeWidgetItem(root);
    seq_brk->setText(0, "Sequenze-Break detect: " + seq_break);
    QTreeWidgetItem* rollover = new QTreeWidgetItem(root);
    rollover->setText(0, "Detected Rollover: " + QString::number(stream.rollover));
}
