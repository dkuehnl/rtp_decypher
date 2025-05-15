#include <QtTest>
#include "../fileutils.h"

class test_main : public QObject
{
    Q_OBJECT

public:
    test_main();
    ~test_main();

private slots:
    void test_add_pos();
    void test_add_neg();
    void test_add_zero();
};

test_main::test_main() {}

test_main::~test_main() {}

void test_main::test_add_pos() {
    QCOMPARE(FileUtils::add_numbers(2, 3), 5);
}

void test_main::test_add_neg() {
    QCOMPARE(FileUtils::add_numbers(-1, -2), -3);
}

void test_main::test_add_zero() {
    QCOMPARE(FileUtils::add_numbers(0, 0), 0);
}

QTEST_APPLESS_MAIN(test_main)

#include "tst_test_main.moc"
