add_executable(rtp_decypher
    main.cpp
    fileutils.h fileutils.cpp
    mainwindow.h mainwindow.cpp mainwindow.ui
)

target_link_libraries(rtp_decypher PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Widgets
    rtp_decypher_lib
)
