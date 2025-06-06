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
    connect(ui->tw_stream_per_connect, &QTreeWidget::doubleClicked, this, &MainWindow::ssrc_doubleClicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

//Buttons:
void MainWindow::on_btn_analyse_clicked() {
    QList<QTreeWidgetItem*> selected_items = ui->tw_stream_per_connect->selectedItems();

    if (selected_items.isEmpty()) {
        QMessageBox::warning(this, "No Stream selected", "You have to select a Stream befor you can analyze it.");
        return;
    }
    uint32_t ssrc = static_cast<uint32_t>(selected_items.first()->text(0).toUInt(nullptr, 16));
    MainWindow::display_analyzed_stream(ssrc);
}

void MainWindow::on_btn_reset_clicked() {
    ui->tw_stream_per_connect->clear();
    ui->tw_stream_results->clear();

}

void MainWindow::on_btn_decypher_clicked() {
    qDebug() << "btn Decypher";

}

void MainWindow::on_btn_exit_clicked() {
    qApp->quit();
}

void MainWindow::on_btn_clear_clicked() {
    qDebug() << "btn Clear";

}

void MainWindow::on_rb_enable_offset_toggled() {
    if (ui->rb_enable_offset->isChecked()) {
        ui->spinner_offset->setEnabled(true);
    } else {
        ui->spinner_offset->setEnabled(false);
    }
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

    size_t offset = 0;
    if (ui->rb_enable_offset->isEnabled()) {
        offset = static_cast<size_t>(ui->spinner_offset->value());
    }

    m_stream_analyzer = std::make_unique<StreamAnalyzer>(selected_stream, offset);
    MainWindow::display_parsed_rtp_streams(selected_ep);
}

void MainWindow::ssrc_doubleClicked(const QModelIndex& index) {
    if (!index.isValid()) return;

    QModelIndex parent_index = index.parent();
    if (parent_index.isValid()) {
        qDebug() << "es gibt ein Parent";
    } else {
        QTreeWidgetItem* item = ui->tw_stream_per_connect->itemFromIndex(index);
        uint32_t ssrc = static_cast<uint32_t>(item->text(0).toUInt(nullptr, 16));
        MainWindow::display_analyzed_stream(ssrc);
    }
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

void MainWindow::display_parsed_rtp_streams(Flow_Endpoints ep) {
    QList<uint32_t> ssrc = m_stream_analyzer->get_ssrcs();

    for (int i = 0; i < ssrc.size(); i++) {
        QTreeWidgetItem* root = new QTreeWidgetItem(ui->tw_stream_per_connect);
        QString hex_value = QString("%1").arg(ssrc[i], 8, 16, QLatin1Char('0')).toUpper();
        hex_value = "0x" + hex_value;
        root->setText(0, hex_value);

        QTreeWidgetItem* endp_child = new QTreeWidgetItem(root);
        QString ep_value =
            QString::fromStdString(ep.source_ip) + ":"
            + QString::number(ep.source_port) + "<->"
            + QString::fromStdString(ep.destination_ip) + ":"
            + QString::number(ep.destination_port);
        endp_child->setText(0, ep_value);

        size_t count = m_stream_analyzer->get_rtp_per_ssrc(ssrc[i]);
        QTreeWidgetItem* count_child = new QTreeWidgetItem(root);
        QString c_value = "Pakets: " + QString::number(count);
        count_child->setText(0, c_value);
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

    ui->tw_stream_results->expandAll();
}
