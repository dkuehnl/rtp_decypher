#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <QTreeView>

namespace FileUtils {

void initialize_fileview(QTreeView* tree_view);
QString get_filepath(QTreeView* tree_view, const QModelIndex& index);

}

#endif // FILEUTILS_H
