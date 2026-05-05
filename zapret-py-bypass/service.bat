@echo off
chcp 65001 >nul
title DPI Bypass (zapret-py)
setlocal EnableExtensions EnableDelayedExpansion

rem ==========================================================================
rem  service.bat — единый центр управления DPI-обходом.
rem  Просто запустите этот файл (двойной клик). Он автоматически попросит
rem  права администратора и покажет текстовое меню.
rem ==========================================================================

cd /d "%~dp0"
set "ROOT=%~dp0"
set "BYPASS_PY=%ROOT%bypass.py"
set "TESTER_PY=%ROOT%tester.py"
set "DOMAINS=%ROOT%domains.txt"
set "LOGS=%ROOT%logs"
if not exist "%LOGS%" mkdir "%LOGS%"

rem -- 1) Автоповышение прав администратора --------------------------------
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo.
    echo  Программе нужны права администратора.
    echo  Сейчас откроется окно UAC — нажмите "Да".
    echo.
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

rem -- 2) Найти Python ------------------------------------------------------
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if "%PY%"=="" ( where python >nul 2>&1 && set "PY=python" )
if "%PY%"=="" (
    echo.
    echo  [ОШИБКА] Python не найден.
    echo  Скачайте Python 3.10+ с https://www.python.org/downloads/
    echo  При установке поставьте галочку "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

rem -- 3) Главное меню ------------------------------------------------------
:MENU
cls
echo ============================================================
echo                  DPI Bypass (zapret-py)                 
echo ============================================================
echo  1. Запустить обход
echo  2. Остановить обход
echo  3. Добавить сайт/IP в список
echo  4. Показать текущий список сайтов
echo  5. Тест подключения (YouTube + X)
echo  6. Статус сервиса
echo  7. Установить зависимости (pydivert)
echo  8. Открыть папку с логами
echo  9. Выйти
echo ============================================================
echo.
set /p CHOICE=Выберите пункт (1-9) и нажмите Enter: 

if "%CHOICE%"=="1" goto START
if "%CHOICE%"=="2" goto STOP
if "%CHOICE%"=="3" goto ADD
if "%CHOICE%"=="4" goto LIST
if "%CHOICE%"=="5" goto TEST
if "%CHOICE%"=="6" goto STATUS
if "%CHOICE%"=="7" goto SETUP
if "%CHOICE%"=="8" goto OPEN_LOGS
if "%CHOICE%"=="9" goto END
echo Неверный пункт меню.
pause
goto MENU

rem -- 1: Запустить обход ---------------------------------------------------
:START
echo.
echo Проверяю pydivert...
%PY% -c "import pydivert" 2>nul
if errorlevel 1 (
    echo  pydivert не установлен. Запускаю установку...
    %PY% -m pip install --quiet --upgrade pip
    %PY% -m pip install --quiet pydivert
    if errorlevel 1 (
        echo  [ОШИБКА] Не удалось установить pydivert.
        echo  Проверьте интернет-соединение и попробуйте ещё раз.
        pause
        goto MENU
    )
)
if exist "%ROOT%bypass.pid" (
    echo  Обход уже запущен. Сначала остановите его (пункт 2).
    pause
    goto MENU
)
echo.
echo Запускаю обход в фоне. Окно с подробностями откроется отдельно.
start "DPI Bypass (running)" /min cmd /c ""%PY%" "%BYPASS_PY%" start"
echo.
echo  Обход запущен. Проверьте YouTube/X в браузере (пункт 5 — тест).
echo  Лог: %LOGS%\log_%DATE:~6,4%-%DATE:~3,2%-%DATE:~0,2%.txt
pause
goto MENU

rem -- 2: Остановить обход --------------------------------------------------
:STOP
echo.
%PY% "%BYPASS_PY%" stop
pause
goto MENU

rem -- 3: Добавить домен ----------------------------------------------------
:ADD
echo.
set /p NEWDOM=Введите домен (пример: youtube.com): 
if "%NEWDOM%"=="" ( echo Пустой ввод. & pause & goto MENU )
%PY% "%BYPASS_PY%" add "%NEWDOM%"
echo.
echo Подсказка: после добавления перезапустите обход (пункт 2 -> пункт 1).
pause
goto MENU

rem -- 4: Список доменов ----------------------------------------------------
:LIST
echo.
echo --- Текущий список (domains.txt) ---
%PY% "%BYPASS_PY%" list
echo ------------------------------------
pause
goto MENU

rem -- 5: Тест подключения --------------------------------------------------
:TEST
echo.
echo Запускаю тест подключения. Это может занять несколько секунд...
echo Подробности также пишутся в logs\log_*.txt
echo.
%PY% "%TESTER_PY%"
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
    echo  ВЕРДИКТ: все сайты грузятся БЫСТРО. Обход работает.
) else if "%RC%"=="2" (
    echo  ВЕРДИКТ: сайты грузятся, но не все БЫСТРО. Возможно, обход не активен
    echo           или нужно подкрутить параметры. Проверьте лог.
) else (
    echo  ВЕРДИКТ: были ошибки подключения. Откройте свежий файл в logs\.
)
pause
goto MENU

rem -- 6: Статус ------------------------------------------------------------
:STATUS
echo.
%PY% "%BYPASS_PY%" status
pause
goto MENU

rem -- 7: Установка зависимостей --------------------------------------------
:SETUP
echo.
echo Устанавливаю pydivert (требует интернет)...
%PY% -m pip install --upgrade pip
%PY% -m pip install -r "%ROOT%requirements.txt"
if errorlevel 1 (
    echo  [ОШИБКА] Установка не удалась.
) else (
    echo  Готово.
)
pause
goto MENU

rem -- 8: Открыть папку с логами --------------------------------------------
:OPEN_LOGS
start "" "%LOGS%"
goto MENU

:END
endlocal
exit /b 0
