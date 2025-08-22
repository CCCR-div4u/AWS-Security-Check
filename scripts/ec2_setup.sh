#!/bin/bash
# EC2 인스턴스 초기 설정 스크립트
# Ubuntu 22.04 LTS 기준

set -e

echo "🚀 AWS 보안 대시보드 EC2 환경 설정 시작..."

# 시스템 업데이트
echo "📦 시스템 패키지 업데이트..."
sudo apt update && sudo apt upgrade -y

# 필수 패키지 설치
echo "🔧 필수 패키지 설치..."
sudo apt install -y \
    software-properties-common \
    build-essential \
    curl \
    wget \
    git \
    unzip \
    nginx \
    supervisor

# Python 3.10 설치 (로컬 버전과 동일)
echo "🐍 Python 3.10 설치..."
sudo apt install -y python3.10 python3.10-venv python3.10-dev python3-pip

# Python 3.10을 기본 python3로 설정
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1

# pip 업그레이드
echo "📦 pip 업그레이드..."
python3 -m pip install --upgrade pip

# 애플리케이션 디렉터리 생성
echo "📁 애플리케이션 디렉터리 생성..."
sudo mkdir -p /opt/aws-security-dashboard
sudo chown $USER:$USER /opt/aws-security-dashboard

# 가상환경 생성
echo "🌐 Python 가상환경 생성..."
cd /opt/aws-security-dashboard
python3 -m venv venv
source venv/bin/activate

# 기본 패키지 설치
pip install --upgrade pip setuptools wheel

echo "✅ EC2 기본 환경 설정 완료!"
echo "📋 다음 단계:"
echo "1. 애플리케이션 코드 업로드"
echo "2. requirements.txt 설치"
echo "3. IAM 역할 설정"
echo "4. 서비스 설정"