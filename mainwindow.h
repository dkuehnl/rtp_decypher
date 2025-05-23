#ifndef MAINWINDOW_H
#define MAINWINDOW_H

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

private slots:
    void on_btn_analyse_clicked();
    void on_btn_reset_clicked();
    void on_btn_decypher_clicked();
    void on_btn_exit_clicked();
    void on_btn_clear_clicked();
};

#endif // MAINWINDOW_H
