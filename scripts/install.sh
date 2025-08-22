#!/bin/bash

# AWS 보안 대시보드 설치 스크립트
# 사용법: sudo ./install.sh

set -e

echo "🚀 AWS 보안 대시보드 설치를 시작합니다..."

# 변수 설정
APP_DIR="/opt/aws-security-dashboard"
SERVICE_USER="ec2-user"
PYTHON_VERSION="3.10"

# 시스템 업데이트
echo "📦 시스템 패키지 업데이트 중..."
if command -v yum &> /dev/null; then
    yum update -y
    yum install -y python3.10 python3.10-pip git curl
    # Amazon Linux의 경우 python3.10 설치
    if ! command -v python3.10 &> /dev/null; then
        amazon-linux-extras install python3.10 -y
    fi
elif command -v apt &> /dev/null; then
    apt update
    apt install -y software-properties-common
    # Python 3.10 설치 (Ubuntu)
    apt install -y python3.10 python3.10-venv python3.10-dev python3-pip git curl
    # python3.10을 기본 python3로 설정
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1
else
    echo "❌ 지원되지 않는 패키지 매니저입니다."
    exit 1
fi

# 애플리케이션 디렉토리 생성
echo "📁 애플리케이션 디렉토리 생성 중..."
mkdir -p $APP_DIR
cd $APP_DIR

# GitHub에서 소스 코드 클론
echo "📋 GitHub에서 소스 코드 다운로드 중..."
if [ -z "$GIT_REPO" ]; then
    GIT_REPO="https://github.com/your-username/aws-security-dashboard.git"
    echo "⚠️  GIT_REPO 환경변수가 설정되지 않았습니다. 기본값 사용: $GIT_REPO"
fi

git clone $GIT_REPO $APP_DIR

# Python 가상환경 생성
echo "🐍 Python 가상환경 생성 중..."
python3 -m venv venv
source venv/bin/activate

# 의존성 설치
echo "📦 Python 패키지 설치 중..."
pip install --upgrade pip
pip install -r requirements.txt

# 권한 설정
echo "🔐 파일 권한 설정 중..."
chown -R $SERVICE_USER:$SERVICE_USER $APP_DIR
chmod +x $APP_DIR/run.sh

# systemd 서비스 설정
echo "⚙️ systemd 서비스 설정 중..."
cp $APP_DIR/systemd/aws-security-dashboard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable aws-security-dashboard

# 방화벽 설정 (firewalld가 있는 경우)
if command -v firewall-cmd &> /dev/null; then
    echo "🔥 방화벽 설정 중..."
    firewall-cmd --permanent --add-port=8501/tcp
    firewall-cmd --reload
fi

# 서비스 시작
echo "🚀 서비스 시작 중..."
systemctl start aws-security-dashboard

# 설치 완료 메시지
echo ""
echo "✅ AWS 보안 대시보드 설치가 완료되었습니다!"
echo ""
echo "📋 설치 정보:"
echo "   - 설치 경로: $APP_DIR"
echo "   - 서비스 사용자: $SERVICE_USER"
echo "   - 포트: 8501"
echo ""
echo "🔧 서비스 관리 명령어:"
echo "   - 상태 확인: sudo systemctl status aws-security-dashboard"
echo "   - 서비스 중지: sudo systemctl stop aws-security-dashboard"
echo "   - 서비스 시작: sudo systemctl start aws-security-dashboard"
echo "   - 로그 확인: sudo journalctl -u aws-security-dashboard -f"
echo ""
echo "🌐 접속 주소: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8501"
echo ""
echo "⚠️  보안 그룹에서 포트 8501을 열어주세요!"