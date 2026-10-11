@echo off
rem Double-click: starts the site analysis console and opens it in the default browser.
rem Extra arguments pass through, for example: run-console.cmd --port 8765
rem Python 3.13 or later: the py launcher first (installed by default), then python on PATH.
chcp 65001 >nul
cd /d "%~dp0.."
set "PY="
py -3 -c "import sys; sys.exit(sys.version_info < (3, 13))" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "import sys; sys.exit(sys.version_info < (3, 13))" >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python 3.13 이상을 찾지 못함. python.org에서 Python 3.13 이상을 설치한 뒤 이 파일을 다시 연다.
  echo 설치 화면의 py launcher 항목을 켜 두면 PATH를 따로 고치지 않아도 이 파일이 Python을 찾는다.
  pause
  exit /b 1
)
echo 콘솔을 시작한다. 이 창을 닫거나 Ctrl+C를 누르면 콘솔과 콘솔이 시작한 분석이 함께 멈춘다.
%PY% -B -m site_analysis.console --open %*
if errorlevel 1 pause
