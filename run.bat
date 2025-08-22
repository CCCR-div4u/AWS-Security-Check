@echo off

REM AWS 보안 대시보드 실행 스크립트 (Windows)

echo AWS 보안 대시보드를 시작합니다...

REM 가상환경 활성화 (존재하는 경우)
if exist "venv\Scripts\activate.bat" (
    echo 가상환경을 활성화합니다...
    call venv\Scripts\activate.bat
)

REM 의존성 설치 확인
echo 의존성을 확인합니다...
pip install -r requirements.txt

REM Streamlit 애플리케이션 실행
echo Streamlit 애플리케이션을 시작합니다...
echo 브라우저에서 http://localhost:8501 또는 http://^<EC2-IP^>:8501로 접속하세요.

streamlit run app.py --server.port 8501 --server.address 0.0.0.0

pause