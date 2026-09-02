#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <QTreeView>

/// @brief Helpers for wiring a QTreeView up as a `.pcap`-filtered filesystem browser.
namespace FileUtils {

/// @brief Configures @p tree_view to browse the filesystem filtered to `.pcap` files.
/// @param tree_view Tree view to configure; takes ownership of a new QFileSystemModel.
void initialize_fileview(QTreeView* tree_view);

/// @brief Resolves the filesystem path selected in @p tree_view.
/// @param tree_view Tree view previously configured via initialize_fileview().
/// @param index Selected model index.
/// @return The absolute path if it is a `.pcap` file, `"dir"` if it is a directory, or an empty string otherwise.
QString get_filepath(QTreeView* tree_view, const QModelIndex& index);

}

#endif // FILEUTILS_H
