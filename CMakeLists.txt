cmake_minimum_required(VERSION 3.20)
project(TotalSweepUninstaller VERSION 8.10.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
include(GNUInstallDirs)

add_executable(totalsweep
    main.cpp

    src/core/ApplicationBackendManager.cpp
    src/core/ApplicationLibrary.cpp

    src/package/rpm/RpmDetector.cpp
    src/package/rpm/RpmBackend.cpp
    src/package/rpm/RpmRemover.cpp
    src/package/flatpak/FlatpakDetector.cpp
    src/package/flatpak/FlatpakBackend.cpp
    src/package/flatpak/FlatpakRemover.cpp
)

target_link_libraries(totalsweep PRIVATE Qt6::Widgets)

install(TARGETS totalsweep RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES org.kde.totalsweep.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES org.kde.totalsweep.svg DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)
