#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "fileutils.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    FileUtils::initialize_fileview(ui->tw_filesystem);
}

MainWindow::~MainWindow()
{
    delete ui;
}

//Buttons:
void MainWindow::on_btn_analyse_clicked() {
    qDebug() << "btn Analyse";
}

void MainWindow::on_btn_reset_clicked() {
    qDebug() << "btn Reset";

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


