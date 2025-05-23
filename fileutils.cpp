#include "fileutils.h"

#include <QFileSystemModel>
#include <QWidget>

void FileUtils::initialize_fileview(QTreeView* tree_view) {
    auto *model = new QFileSystemModel;
    model->setRootPath(QDir::homePath());
    model->setNameFilters({"*.pcap"});
    model->setNameFilterDisables(false);

    tree_view->setModel(model);
    model->setHeaderData(0, Qt::Horizontal, QVariant(QString("PCAP-File")), Qt::DisplayRole);

    tree_view->setRootIndex(model->index(QDir::homePath()));
    tree_view->setAlternatingRowColors(true);
    tree_view->setAnimated(true);

    tree_view->hideColumn(1);
    tree_view->hideColumn(2);
    tree_view->hideColumn(3);

}
