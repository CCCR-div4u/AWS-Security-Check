#!/bin/bash

# AWS 보안 대시보드 배포 스크립트
# EC2 인스턴스에 자동 배포

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 로그 함수
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 변수 설정
APP_NAME="aws-security-dashboard"
APP_DIR="/opt/$APP_NAME"
BACKUP_DIR="/opt/${APP_NAME}-backup-$(date +%Y%m%d-%H%M%S)"
SERVICE_NAME="aws-security-dashboard"

log_info "🚀 AWS 보안 대시보드 배포를 시작합니다..."

# 루트 권한 확인
if [[ $EUID -ne 0 ]]; then
   log_error "이 스크립트는 root 권한으로 실행해야 합니다."
   exit 1
fi

# 기존 설치 확인 및 백업
if [ -d "$APP_DIR" ]; then
    log_warning "기존 설치가 발견되었습니다. 백업을 생성합니다..."
    
    # 서비스 중지
    if systemctl is-active --quiet $SERVICE_NAME; then
        log_info "서비스를 중지합니다..."
        systemctl stop $SERVICE_NAME
    fi
    
    # 백업 생성
    cp -r $APP_DIR $BACKUP_DIR
    log_success "백업이 생성되었습니다: $BACKUP_DIR"
fi

# 임시 디렉토리에서 작업
TEMP_DIR="/tmp/$APP_NAME-deploy"
rm -rf $TEMP_DIR
mkdir -p $TEMP_DIR
cd $TEMP_DIR

# GitHub에서 소스 코드 다운로드
log_info "GitHub에서 소스 코드를 다운로드합니다..."
if [ -z "$GIT_REPO" ]; then
    GIT_REPO="https://github.com/your-username/aws-security-dashboard.git"
    log_warning "GIT_REPO 환경변수가 설정되지 않았습니다. 기본값을 사용합니다: $GIT_REPO"
fi

git clone $GIT_REPO .

# 애플리케이션 디렉토리 준비
log_info "애플리케이션 디렉토리를 준비합니다..."
mkdir -p $APP_DIR
cp -r * $APP_DIR/

# Python 가상환경 설정
log_info "Python 가상환경을 설정합니다..."
cd $APP_DIR

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 권한 설정
log_info "파일 권한을 설정합니다..."
chown -R ec2-user:ec2-user $APP_DIR
chmod +x $APP_DIR/run.sh
chmod +x $APP_DIR/scripts/*.sh

# systemd 서비스 설정
log_info "systemd 서비스를 설정합니다..."
if [ -f "$APP_DIR/systemd/$SERVICE_NAME.service" ]; then
    cp $APP_DIR/systemd/$SERVICE_NAME.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
fi

# 설정 파일 확인
log_info "설정을 확인합니다..."
if [ ! -f "$APP_DIR/app.py" ]; then
    log_error "app.py 파일을 찾을 수 없습니다."
    exit 1
fi

if [ ! -f "$APP_DIR/requirements.txt" ]; then
    log_error "requirements.txt 파일을 찾을 수 없습니다."
    exit 1
fi

# 헬스체크 함수
health_check() {
    local max_attempts=30
    local attempt=1
    
    log_info "애플리케이션 헬스체크를 수행합니다..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s http://localhost:8501/_stcore/health > /dev/null 2>&1; then
            log_success "애플리케이션이 정상적으로 시작되었습니다!"
            return 0
        fi
        
        log_info "헬스체크 시도 $attempt/$max_attempts..."
        sleep 2
        ((attempt++))
    done
    
    log_error "애플리케이션 시작에 실패했습니다."
    return 1
}

# 서비스 시작
log_info "서비스를 시작합니다..."
systemctl start $SERVICE_NAME

# 헬스체크 수행
if health_check; then
    log_success "배포가 성공적으로 완료되었습니다!"
    
    # 서비스 상태 표시
    echo ""
    log_info "서비스 상태:"
    systemctl status $SERVICE_NAME --no-pager -l
    
    echo ""
    log_info "접속 정보:"
    PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")
    echo "   🌐 URL: http://$PUBLIC_IP:8501"
    echo "   📋 로그: sudo journalctl -u $SERVICE_NAME -f"
    echo "   ⚙️  관리: sudo systemctl {start|stop|restart|status} $SERVICE_NAME"
    
    # 백업 정리 (성공 시)
    if [ -d "$BACKUP_DIR" ]; then
        log_info "이전 백업을 정리합니다..."
        rm -rf $BACKUP_DIR
    fi
    
else
    log_error "배포에 실패했습니다."
    
    # 롤백
    if [ -d "$BACKUP_DIR" ]; then
        log_warning "이전 버전으로 롤백합니다..."
        systemctl stop $SERVICE_NAME
        rm -rf $APP_DIR
        mv $BACKUP_DIR $APP_DIR
        systemctl start $SERVICE_NAME
        log_info "롤백이 완료되었습니다."
    fi
    
    exit 1
fi

# 임시 파일 정리
rm -rf $TEMP_DIR

log_success "🎉 배포가 완료되었습니다!"