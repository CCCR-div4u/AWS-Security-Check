"""
AWS 운영자를 위한 보안 대시보드
AWS 계정의 보안 상태를 점검하고 위협 사항을 식별하는 웹 애플리케이션
"""

import streamlit as st
import boto3
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
from botocore.exceptions import ClientError, NoCredentialsError

# Streamlit 페이지 설정
st.set_page_config(
    page_title="AWS 보안 대시보드",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    """메인 애플리케이션 함수"""
    
    # 페이지 헤더
    st.title("🔒 AWS 운영자를 위한 보안 대시보드")
    st.markdown("---")
    
    # 세션 상태 초기화
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'aws_session' not in st.session_state:
        st.session_state.aws_session = None
    if 'scan_completed' not in st.session_state:
        st.session_state.scan_completed = False
    
    # 인증되지 않은 경우 자격 증명 입력 화면 표시
    if not st.session_state.authenticated:
        show_authentication_form()
    else:
        # 인증된 경우 대시보드 표시
        if st.session_state.scan_completed:
            show_dashboard()
        else:
            show_scan_interface()

def show_authentication_form():
    """AWS 자격 증명 입력 폼 표시"""
    
    st.subheader("🔐 AWS 자격 증명 입력")
    st.info("AWS 계정에 연결하기 위해 자격 증명을 입력하세요.")
    
    # 연결 방법 선택
    st.markdown("### 연결 방법 선택")
    
    # 자격 증명 입력 폼
    with st.form("aws_credentials"):
        # 인스턴스 프로파일 사용 옵션
        use_instance_profile = st.checkbox(
            "🏢 EC2 인스턴스 프로파일 사용", 
            help="EC2에서 실행 중인 경우 인스턴스 프로파일을 사용할 수 있습니다. 이 옵션을 선택하면 별도의 자격 증명 입력이 불필요합니다."
        )
        
        st.markdown("---")
        
        # 인스턴스 프로파일 사용 여부에 따른 입력 필드 활성화/비활성화
        if not use_instance_profile:
            st.markdown("### 🔑 AWS 자격 증명 정보")
            
            col1, col2 = st.columns(2)
            
            with col1:
                account_id = st.text_input(
                    "AWS 계정 ID *", 
                    placeholder="123456789012",
                    help="12자리 AWS 계정 ID를 입력하세요.",
                    max_chars=12
                )
                
                access_key = st.text_input(
                    "Access Key ID *", 
                    placeholder="AKIAIOSFODNN7EXAMPLE",
                    help="AWS IAM에서 생성한 Access Key ID를 입력하세요.",
                    max_chars=128
                )
            
            with col2:
                secret_key = st.text_input(
                    "Secret Access Key *", 
                    type="password", 
                    placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    help="Access Key에 대응하는 Secret Access Key를 입력하세요."
                )
                
                region = st.selectbox(
                    "AWS 리전 *",
                    options=[
                        "ap-northeast-2",  # Seoul
                        "us-east-1",       # N. Virginia
                        "us-west-2",       # Oregon
                        "eu-west-1",       # Ireland
                        "ap-southeast-1",  # Singapore
                        "ap-northeast-1",  # Tokyo
                        "eu-central-1",    # Frankfurt
                        "us-west-1",       # N. California
                        "ap-south-1",      # Mumbai
                        "sa-east-1"        # São Paulo
                    ],
                    index=0,  # ap-northeast-2 (Seoul) as default
                    help="AWS 리소스를 조회할 기본 리전을 선택하세요."
                )
            
            # 입력 검증 메시지
            st.markdown("**필수 입력 항목 (*)을 모두 입력해주세요.**")
            
            # 보안 안내
            with st.expander("🛡️ 보안 안내사항"):
                st.markdown("""
                - 입력한 자격 증명은 메모리에서만 처리되며 파일에 저장되지 않습니다.
                - 세션 종료 시 모든 자격 증명 정보가 자동으로 삭제됩니다.
                - 읽기 전용 권한만 사용하여 AWS 리소스를 조회합니다.
                - 프로덕션 환경에서는 최소 권한 원칙을 적용한 IAM 역할 사용을 권장합니다.
                """)
        
        else:
            st.markdown("### 🏢 인스턴스 프로파일 설정")
            account_id = ""
            access_key = ""
            secret_key = ""
            
            region = st.selectbox(
                "AWS 리전 *",
                options=[
                    "ap-northeast-2",  # Seoul
                    "us-east-1",       # N. Virginia
                    "us-west-2",       # Oregon
                    "eu-west-1",       # Ireland
                    "ap-southeast-1",  # Singapore
                    "ap-northeast-1",  # Tokyo
                    "eu-central-1",    # Frankfurt
                    "us-west-1",       # N. California
                    "ap-south-1",      # Mumbai
                    "sa-east-1"        # São Paulo
                ],
                index=0,
                help="AWS 리소스를 조회할 기본 리전을 선택하세요."
            )
            
            st.info("✅ 인스턴스 프로파일을 사용합니다. EC2 인스턴스에 연결된 IAM 역할의 권한을 사용하여 AWS 리소스에 접근합니다.")
            
            # 인스턴스 프로파일 요구사항 안내
            with st.expander("📋 인스턴스 프로파일 요구사항"):
                st.markdown("""
                **EC2 인스턴스에 다음 권한이 포함된 IAM 역할이 연결되어 있어야 합니다:**
                
                - `iam:ListUsers`, `iam:ListRoles`, `iam:ListGroups`
                - `iam:GetUser`, `iam:GetRole`, `iam:GetAccountSummary`
                - `iam:ListAttachedUserPolicies`, `iam:ListAttachedRolePolicies`
                - `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:LookupEvents`
                - `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`
                - `guardduty:ListDetectors`, `guardduty:GetFindings`, `guardduty:ListFindings`
                - `wafv2:ListWebACLs`, `wafv2:GetWebACL`
                - `sts:GetCallerIdentity`
                """)
        
        st.markdown("---")
        
        # 계정 점검 버튼
        submitted = st.form_submit_button(
            "🔍 계정 점검 시작", 
            type="primary",
            use_container_width=True,
            help="입력한 자격 증명으로 AWS 계정 연결을 테스트합니다."
        )
        
        if submitted:
            # 입력 검증
            if not use_instance_profile:
                if not all([account_id, access_key, secret_key, region]):
                    st.error("❌ 모든 필수 입력 항목을 입력해주세요.")
                    return
                
                # 계정 ID 형식 검증
                if not account_id.isdigit() or len(account_id) != 12:
                    st.error("❌ AWS 계정 ID는 12자리 숫자여야 합니다.")
                    return
                
                # Access Key 형식 검증
                if not access_key.startswith('AKIA') or len(access_key) != 20:
                    st.error("❌ Access Key ID 형식이 올바르지 않습니다. (AKIA로 시작하는 20자리)")
                    return
            
            validate_aws_credentials(use_instance_profile, account_id, access_key, secret_key, region)

def validate_aws_credentials(use_instance_profile, account_id, access_key, secret_key, region):
    """AWS 자격 증명 유효성 검증"""
    
    try:
        with st.spinner("🔄 AWS 계정 연결을 확인하는 중..."):
            # boto3 세션 생성
            if use_instance_profile:
                # 인스턴스 프로파일 사용
                st.info("🏢 EC2 인스턴스 프로파일을 사용하여 연결 중...")
                session = boto3.Session(region_name=region)
            else:
                # 수동 자격 증명 입력
                st.info("🔑 입력한 자격 증명으로 연결 중...")
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
            
            # 1단계: STS를 사용하여 기본 자격 증명 검증
            st.info("1️⃣ 자격 증명 유효성 검증 중...")
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            
            # 계정 ID 일치 확인 (수동 입력인 경우)
            actual_account_id = identity.get('Account')
            if not use_instance_profile and account_id != actual_account_id:
                st.error(f"❌ 입력한 계정 ID({account_id})와 실제 계정 ID({actual_account_id})가 일치하지 않습니다.")
                return
            
            # 2단계: 필요한 권한 확인
            st.info("2️⃣ 필요한 AWS 권한 확인 중...")
            permission_check_results = check_required_permissions(session)
            
            # 3단계: 연결 정보 저장 및 결과 표시
            st.info("3️⃣ 연결 정보 저장 중...")
            
            # 세션 상태 업데이트
            st.session_state.authenticated = True
            st.session_state.aws_session = session
            st.session_state.account_info = {
                'account_id': actual_account_id,
                'user_arn': identity.get('Arn'),
                'user_id': identity.get('UserId'),
                'region': region,
                'use_instance_profile': use_instance_profile,
                'permissions': permission_check_results
            }
            
            # 성공 메시지 표시
            st.success("✅ AWS 계정 연결이 성공적으로 완료되었습니다!")
            
            # 연결 정보 표시
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("계정 ID", actual_account_id)
            with col2:
                st.metric("리전", region)
            with col3:
                connection_type = "인스턴스 프로파일" if use_instance_profile else "수동 입력"
                st.metric("연결 방식", connection_type)
            
            # 사용자 정보 표시
            st.info(f"👤 연결된 사용자: {identity.get('Arn')}")
            
            # 권한 확인 결과 표시
            display_permission_check_results(permission_check_results)
            
            # 페이지 새로고침
            st.rerun()
            
    except NoCredentialsError:
        st.error("❌ AWS 자격 증명이 제공되지 않았습니다.")
        if use_instance_profile:
            st.error("💡 EC2 인스턴스에 IAM 역할이 연결되어 있는지 확인해주세요.")
        else:
            st.error("💡 Access Key ID와 Secret Access Key를 다시 확인해주세요.")
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'InvalidUserID.NotFound':
            st.error("❌ 유효하지 않은 AWS 사용자입니다.")
            st.error("💡 Access Key가 삭제되었거나 비활성화되었을 수 있습니다.")
        elif error_code == 'SignatureDoesNotMatch':
            st.error("❌ Access Key 또는 Secret Key가 올바르지 않습니다.")
            st.error("💡 자격 증명을 다시 확인하고 복사/붙여넣기 시 공백이 포함되지 않았는지 확인해주세요.")
        elif error_code == 'AccessDenied':
            st.error("❌ AWS 리소스에 접근할 권한이 없습니다.")
            st.error("💡 최소한 'sts:GetCallerIdentity' 권한이 필요합니다.")
        elif error_code == 'TokenRefreshRequired':
            st.error("❌ 임시 자격 증명이 만료되었습니다.")
            st.error("💡 새로운 임시 자격 증명을 발급받아 주세요.")
        elif error_code == 'UnauthorizedOperation':
            st.error("❌ 해당 작업을 수행할 권한이 없습니다.")
            st.error("💡 IAM 정책에서 필요한 권한을 확인해주세요.")
        else:
            st.error(f"❌ AWS API 오류: {error_code}")
            st.error(f"💡 상세 메시지: {error_message}")
            
    except Exception as e:
        st.error(f"❌ 예상치 못한 오류가 발생했습니다: {str(e)}")
        st.error("💡 네트워크 연결을 확인하거나 잠시 후 다시 시도해주세요.")

def check_required_permissions(session):
    """필요한 AWS 권한 확인"""
    
    permission_results = {
        'iam': {'status': 'unknown', 'message': ''},
        'cloudtrail': {'status': 'unknown', 'message': ''},
        's3': {'status': 'unknown', 'message': ''},
        'guardduty': {'status': 'unknown', 'message': ''},
        'waf': {'status': 'unknown', 'message': ''}
    }
    
    try:
        # IAM 권한 확인
        iam_client = session.client('iam')
        try:
            iam_client.get_account_summary()
            permission_results['iam'] = {'status': 'success', 'message': 'IAM 읽기 권한 확인됨'}
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                permission_results['iam'] = {'status': 'warning', 'message': 'IAM 권한 부족 (일부 기능 제한)'}
            else:
                permission_results['iam'] = {'status': 'error', 'message': f'IAM 권한 확인 실패: {e.response["Error"]["Code"]}'}
        
        # CloudTrail 권한 확인
        cloudtrail_client = session.client('cloudtrail')
        try:
            cloudtrail_client.describe_trails()
            permission_results['cloudtrail'] = {'status': 'success', 'message': 'CloudTrail 읽기 권한 확인됨'}
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                permission_results['cloudtrail'] = {'status': 'warning', 'message': 'CloudTrail 권한 부족 (일부 기능 제한)'}
            else:
                permission_results['cloudtrail'] = {'status': 'error', 'message': f'CloudTrail 권한 확인 실패: {e.response["Error"]["Code"]}'}
        
        # S3 권한 확인
        s3_client = session.client('s3')
        try:
            s3_client.list_buckets()
            permission_results['s3'] = {'status': 'success', 'message': 'S3 읽기 권한 확인됨'}
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                permission_results['s3'] = {'status': 'warning', 'message': 'S3 권한 부족 (일부 기능 제한)'}
            else:
                permission_results['s3'] = {'status': 'error', 'message': f'S3 권한 확인 실패: {e.response["Error"]["Code"]}'}
        
        # GuardDuty 권한 확인
        guardduty_client = session.client('guardduty')
        try:
            guardduty_client.list_detectors()
            permission_results['guardduty'] = {'status': 'success', 'message': 'GuardDuty 읽기 권한 확인됨'}
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                permission_results['guardduty'] = {'status': 'warning', 'message': 'GuardDuty 권한 부족 (일부 기능 제한)'}
            else:
                permission_results['guardduty'] = {'status': 'error', 'message': f'GuardDuty 권한 확인 실패: {e.response["Error"]["Code"]}'}
        
        # WAF 권한 확인
        wafv2_client = session.client('wafv2')
        try:
            wafv2_client.list_web_acls(Scope='REGIONAL')
            permission_results['waf'] = {'status': 'success', 'message': 'WAF 읽기 권한 확인됨'}
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                permission_results['waf'] = {'status': 'warning', 'message': 'WAF 권한 부족 (일부 기능 제한)'}
            else:
                permission_results['waf'] = {'status': 'error', 'message': f'WAF 권한 확인 실패: {e.response["Error"]["Code"]}'}
                
    except Exception as e:
        st.warning(f"⚠️ 권한 확인 중 오류 발생: {str(e)}")
    
    return permission_results

def display_permission_check_results(permission_results):
    """권한 확인 결과 표시"""
    
    st.markdown("### 🔐 권한 확인 결과")
    
    for service, result in permission_results.items():
        status = result['status']
        message = result['message']
        
        if status == 'success':
            st.success(f"✅ {service.upper()}: {message}")
        elif status == 'warning':
            st.warning(f"⚠️ {service.upper()}: {message}")
        elif status == 'error':
            st.error(f"❌ {service.upper()}: {message}")
        else:
            st.info(f"ℹ️ {service.upper()}: 권한 확인 중...")
    
    # 권한 부족 시 안내 메시지
    has_warnings = any(result['status'] == 'warning' for result in permission_results.values())
    has_errors = any(result['status'] == 'error' for result in permission_results.values())
    
    if has_warnings or has_errors:
        with st.expander("💡 권한 부족 시 해결 방법"):
            st.markdown("""
            **권한이 부족한 서비스가 있습니다. 다음 방법으로 해결할 수 있습니다:**
            
            1. **IAM 정책 확인**: 사용 중인 IAM 사용자/역할에 필요한 권한이 포함되어 있는지 확인
            2. **읽기 전용 정책 연결**: `ReadOnlyAccess` 정책을 연결하면 대부분의 기능을 사용할 수 있습니다
            3. **최소 권한 정책**: 보안을 위해 필요한 권한만 포함된 커스텀 정책 생성
            
            **권한이 부족해도 기본적인 보안 스캔은 가능하지만, 일부 기능이 제한될 수 있습니다.**
            """)
    else:
        st.success("🎉 모든 필요한 권한이 확인되었습니다! 전체 기능을 사용할 수 있습니다.")

def show_scan_interface():
    """보안 스캔 시작 인터페이스"""
    
    st.subheader("🔍 보안 스캔")
    
    # 계정 정보 표시
    if 'account_info' in st.session_state:
        account_info = st.session_state.account_info
        
        st.markdown("### 📊 연결된 계정 정보")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("계정 ID", account_info['account_id'])
        with col2:
            st.metric("리전", account_info['region'])
        with col3:
            connection_type = "인스턴스 프로파일" if account_info['use_instance_profile'] else "수동 입력"
            st.metric("연결 방식", connection_type)
        with col4:
            # 권한 상태 요약
            permissions = account_info.get('permissions', {})
            success_count = sum(1 for p in permissions.values() if p.get('status') == 'success')
            total_count = len(permissions)
            st.metric("권한 상태", f"{success_count}/{total_count}")
    
    st.markdown("---")
    
    # 스캔 옵션 설정
    st.markdown("### ⚙️ 스캔 옵션")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**스캔할 서비스 선택:**")
        scan_iam = st.checkbox("🔐 IAM 리소스 스캔", value=True, help="IAM 사용자, 역할, 그룹 및 보안 위험 요소 검사")
        scan_cloudtrail = st.checkbox("📋 CloudTrail 로그 분석", value=True, help="API 호출 이력 및 의심스러운 활동 탐지")
        scan_s3 = st.checkbox("🗄️ S3 보안 검사", value=True, help="S3 버킷 공개 설정 및 암호화 상태 확인")
    
    with col2:
        st.markdown("**고급 스캔 옵션:**")
        scan_guardduty = st.checkbox("🛡️ GuardDuty 발견 사항", value=True, help="GuardDuty 위협 탐지 결과 조회")
        scan_waf = st.checkbox("🌐 WAF 설정 검사", value=True, help="WAF 웹 ACL 및 규칙 설정 확인")
        deep_scan = st.checkbox("🔬 심화 분석", value=False, help="더 상세한 보안 분석 (시간이 더 소요됨)")
    
    # 선택된 스캔 옵션 저장
    scan_options = {
        'iam': scan_iam,
        'cloudtrail': scan_cloudtrail,
        's3': scan_s3,
        'guardduty': scan_guardduty,
        'waf': scan_waf,
        'deep_scan': deep_scan
    }
    
    st.session_state.scan_options = scan_options
    
    st.markdown("---")
    
    # 스캔 예상 시간 표시
    estimated_time = calculate_estimated_scan_time(scan_options)
    st.info(f"⏱️ 예상 스캔 시간: 약 {estimated_time}분")
    
    # 보안 스캔 시작 버튼
    selected_services = [service for service, enabled in scan_options.items() if enabled and service != 'deep_scan']
    
    if not selected_services:
        st.warning("⚠️ 최소 하나 이상의 서비스를 선택해주세요.")
        st.button("🔍 보안 스캔 시작", disabled=True, use_container_width=True)
    else:
        st.success(f"✅ {len(selected_services)}개 서비스 스캔 준비 완료")
        
        if st.button("🔍 보안 스캔 시작", type="primary", use_container_width=True):
            start_security_scan(scan_options)
    
    # 스캔 안내사항
    with st.expander("📖 스캔 안내사항"):
        st.markdown("""
        **보안 스캔 과정:**
        1. **IAM 리소스 스캔**: 사용자, 역할, 그룹의 권한 및 보안 위험 요소 분석
        2. **CloudTrail 분석**: 최근 24시간 API 호출 이력 및 의심스러운 활동 탐지
        3. **S3 보안 검사**: 버킷 공개 설정, 암호화, 액세스 정책 확인
        4. **GuardDuty 조회**: 위협 탐지 서비스의 발견 사항 수집
        5. **WAF 설정 확인**: 웹 애플리케이션 방화벽 규칙 및 설정 검사
        
        **주의사항:**
        - 스캔 중에는 브라우저를 닫지 마세요
        - 대용량 계정의 경우 스캔 시간이 더 소요될 수 있습니다
        - 읽기 전용 권한만 사용하므로 AWS 리소스가 변경되지 않습니다
        """)

def calculate_estimated_scan_time(scan_options):
    """스캔 예상 시간 계산"""
    base_time = 0
    
    if scan_options.get('iam'):
        base_time += 1.5
    if scan_options.get('cloudtrail'):
        base_time += 2.0
    if scan_options.get('s3'):
        base_time += 1.0
    if scan_options.get('guardduty'):
        base_time += 0.5
    if scan_options.get('waf'):
        base_time += 0.5
    if scan_options.get('deep_scan'):
        base_time *= 1.5
    
    return max(1, int(base_time))

def start_security_scan(scan_options):
    """보안 스캔 시작"""
    
    # 스캔 시작 시간 기록
    scan_start_time = datetime.now()
    st.session_state.scan_start_time = scan_start_time
    
    # 스캔 결과 초기화
    st.session_state.scan_results = {
        'iam': {'status': 'pending', 'data': {}, 'issues': []},
        'cloudtrail': {'status': 'pending', 'data': {}, 'issues': []},
        's3': {'status': 'pending', 'data': {}, 'issues': []},
        'guardduty': {'status': 'pending', 'data': {}, 'issues': []},
        'waf': {'status': 'pending', 'data': {}, 'issues': []},
        'summary': {'total_issues': 0, 'high_risk': 0, 'medium_risk': 0, 'low_risk': 0}
    }
    
    # 선택된 스캔 단계 생성
    scan_steps = []
    if scan_options.get('iam'):
        scan_steps.append(('iam', '🔐 IAM 리소스 스캔 중...', perform_iam_scan))
    if scan_options.get('cloudtrail'):
        scan_steps.append(('cloudtrail', '📋 CloudTrail 로그 분석 중...', perform_cloudtrail_scan))
    if scan_options.get('s3'):
        scan_steps.append(('s3', '🗄️ S3 보안 검사 중...', perform_s3_scan))
    if scan_options.get('guardduty'):
        scan_steps.append(('guardduty', '🛡️ GuardDuty 발견 사항 조회 중...', perform_guardduty_scan))
    if scan_options.get('waf'):
        scan_steps.append(('waf', '🌐 WAF 설정 확인 중...', perform_waf_scan))
    
    # 진행률 표시 컨테이너
    progress_container = st.container()
    
    with progress_container:
        st.markdown("### 🔄 스캔 진행 상황")
        progress_bar = st.progress(0)
        status_text = st.empty()
        detail_text = st.empty()
        
        # 스캔 단계별 상태 표시
        step_status_container = st.container()
    
    try:
        aws_session = st.session_state.aws_session
        total_steps = len(scan_steps)
        
        for i, (service, description, scan_function) in enumerate(scan_steps):
            # 현재 단계 표시
            current_progress = i / total_steps
            progress_bar.progress(current_progress)
            status_text.markdown(f"**{description}**")
            detail_text.info(f"단계 {i+1}/{total_steps}: {service.upper()} 서비스 분석 중...")
            
            # 단계별 상태 업데이트
            with step_status_container:
                display_scan_progress(scan_steps, i)
            
            try:
                # 실제 스캔 함수 호출
                scan_result = scan_function(aws_session, scan_options.get('deep_scan', False))
                st.session_state.scan_results[service] = {
                    'status': 'completed',
                    'data': scan_result.get('data', {}),
                    'issues': scan_result.get('issues', [])
                }
                
                # 성공 메시지
                detail_text.success(f"✅ {service.upper()} 스캔 완료 - {len(scan_result.get('issues', []))}개 이슈 발견")
                
            except Exception as e:
                # 개별 스캔 실패 처리
                st.session_state.scan_results[service] = {
                    'status': 'failed',
                    'data': {},
                    'issues': [],
                    'error': str(e)
                }
                detail_text.warning(f"⚠️ {service.upper()} 스캔 실패: {str(e)}")
            
            # 시뮬레이션을 위한 대기 (실제 구현에서는 제거)
            import time
            time.sleep(0.5)
        
        # 최종 분석 단계
        progress_bar.progress(0.95)
        status_text.markdown("**🔍 보안 이슈 분석 및 요약 중...**")
        detail_text.info("수집된 데이터를 분석하여 보안 이슈를 분류하고 있습니다...")
        
        # 보안 이슈 요약 생성
        generate_security_summary()
        
        # 스캔 완료
        progress_bar.progress(1.0)
        status_text.markdown("**✅ 보안 스캔 완료!**")
        
        # 스캔 완료 시간 계산
        scan_end_time = datetime.now()
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        
        detail_text.success(f"🎉 모든 스캔이 완료되었습니다! (소요 시간: {scan_duration:.1f}초)")
        
        # 스캔 완료 상태 업데이트
        st.session_state.scan_completed = True
        st.session_state.scan_end_time = scan_end_time
        
        # 잠시 후 대시보드로 전환
        time.sleep(2)
        st.rerun()
        
    except Exception as e:
        progress_bar.progress(0)
        status_text.markdown("**❌ 스캔 중 오류 발생**")
        detail_text.error(f"스캔 중 예상치 못한 오류가 발생했습니다: {str(e)}")
        st.error("💡 네트워크 연결을 확인하거나 AWS 권한을 다시 확인해주세요.")

def display_scan_progress(scan_steps, current_step):
    """스캔 진행 상태를 단계별로 표시"""
    
    cols = st.columns(len(scan_steps))
    
    for i, (service, description, _) in enumerate(scan_steps):
        with cols[i]:
            if i < current_step:
                st.success(f"✅ {service.upper()}")
            elif i == current_step:
                st.info(f"🔄 {service.upper()}")
            else:
                st.write(f"⏳ {service.upper()}")

def generate_security_summary():
    """보안 이슈 요약 생성"""
    
    scan_results = st.session_state.scan_results
    
    # 통합 보안 이슈 분석
    integrated_analysis = analyze_integrated_security_issues(scan_results)
    
    # 기본 통계
    total_issues = 0
    high_risk = 0
    medium_risk = 0
    low_risk = 0
    
    # 서비스별 이슈 분류
    service_issues = {
        'iam': {'high': 0, 'medium': 0, 'low': 0, 'issues': []},
        'cloudtrail': {'high': 0, 'medium': 0, 'low': 0, 'issues': []},
        's3': {'high': 0, 'medium': 0, 'low': 0, 'issues': []},
        'guardduty': {'high': 0, 'medium': 0, 'low': 0, 'issues': []},
        'waf': {'high': 0, 'medium': 0, 'low': 0, 'issues': []}
    }
    
    # 이슈 유형별 분류
    issue_categories = {
        'access_control': {'count': 0, 'issues': []},
        'data_protection': {'count': 0, 'issues': []},
        'monitoring': {'count': 0, 'issues': []},
        'network_security': {'count': 0, 'issues': []},
        'threat_detection': {'count': 0, 'issues': []},
        'compliance': {'count': 0, 'issues': []}
    }
    
    # 각 서비스별 이슈 집계 및 분류
    for service, result in scan_results.items():
        if service == 'summary':
            continue
            
        issues = result.get('issues', [])
        total_issues += len(issues)
        
        for issue in issues:
            risk_level = issue.get('risk_level', 'low')
            
            # 위험도별 집계
            if risk_level == 'high':
                high_risk += 1
                service_issues[service]['high'] += 1
            elif risk_level == 'medium':
                medium_risk += 1
                service_issues[service]['medium'] += 1
            else:
                low_risk += 1
                service_issues[service]['low'] += 1
            
            # 이슈를 서비스별로 저장
            service_issues[service]['issues'].append(issue)
            
            # 이슈 카테고리 분류
            category = categorize_security_issue(issue, service)
            if category in issue_categories:
                issue_categories[category]['count'] += 1
                issue_categories[category]['issues'].append({
                    'service': service,
                    'issue': issue
                })
    
    # 보안 점수 계산
    security_score = calculate_security_score(high_risk, medium_risk, low_risk, scan_results)
    
    # 우선순위 이슈 선별 (상위 10개)
    priority_issues = get_priority_issues(scan_results)
    
    # 서비스별 보안 상태 평가
    service_health = evaluate_service_health(scan_results)
    
    # 규정 준수 상태 평가
    compliance_status = evaluate_compliance_status(scan_results)
    
    # 요약 정보 저장
    st.session_state.scan_results['summary'] = {
        'total_issues': total_issues,
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk,
        'services_scanned': len([s for s in scan_results.keys() if s != 'summary' and scan_results[s]['status'] == 'completed']),
        'services_failed': len([s for s in scan_results.keys() if s != 'summary' and scan_results[s]['status'] == 'failed']),
        'security_score': security_score,
        'service_issues': service_issues,
        'issue_categories': issue_categories,
        'priority_issues': priority_issues,
        'service_health': service_health,
        'compliance_status': compliance_status,
        'integrated_analysis': integrated_analysis,
        'recommendations': generate_integrated_recommendations(scan_results, integrated_analysis)
    }

def analyze_integrated_security_issues(scan_results):
    """통합 보안 이슈 분석"""
    
    analysis = {
        'critical_gaps': [],
        'security_patterns': [],
        'risk_correlations': [],
        'overall_posture': 'unknown'
    }
    
    # 1. 중요한 보안 격차 식별
    iam_issues = scan_results.get('iam', {}).get('issues', [])
    cloudtrail_issues = scan_results.get('cloudtrail', {}).get('issues', [])
    s3_issues = scan_results.get('s3', {}).get('issues', [])
    guardduty_issues = scan_results.get('guardduty', {}).get('issues', [])
    waf_issues = scan_results.get('waf', {}).get('issues', [])
    
    # CloudTrail이 비활성화되고 GuardDuty도 없는 경우
    has_cloudtrail_disabled = any(issue.get('type') == 'no_cloudtrail' for issue in cloudtrail_issues)
    has_guardduty_disabled = any(issue.get('type') == 'guardduty_not_enabled' for issue in guardduty_issues)
    
    if has_cloudtrail_disabled and has_guardduty_disabled:
        analysis['critical_gaps'].append({
            'type': 'no_monitoring',
            'severity': 'critical',
            'description': 'CloudTrail과 GuardDuty가 모두 비활성화되어 보안 모니터링이 불가능',
            'impact': '보안 사고 탐지 및 대응 능력 부재',
            'recommendation': 'CloudTrail과 GuardDuty를 즉시 활성화하세요.'
        })
    
    # 루트 계정 보안 + MFA 미설정 조합
    has_root_issues = any('root' in issue.get('type', '') for issue in iam_issues)
    has_mfa_issues = any('mfa' in issue.get('type', '') for issue in iam_issues)
    
    if has_root_issues and has_mfa_issues:
        analysis['critical_gaps'].append({
            'type': 'root_account_vulnerable',
            'severity': 'critical',
            'description': '루트 계정 보안이 취약하고 MFA가 광범위하게 미설정됨',
            'impact': '계정 탈취 시 전체 AWS 환경 장악 가능',
            'recommendation': '루트 계정 보안을 강화하고 모든 사용자에게 MFA를 적용하세요.'
        })
    
    # 공개 S3 버킷 + WAF 미설정 조합
    has_public_s3 = any('public' in issue.get('type', '') for issue in s3_issues)
    has_no_waf = any(issue.get('type') == 'no_waf_configured' for issue in waf_issues)
    
    if has_public_s3 and has_no_waf:
        analysis['critical_gaps'].append({
            'type': 'exposed_data_no_protection',
            'severity': 'high',
            'description': '공개 S3 버킷이 존재하고 WAF 보호가 없음',
            'impact': '데이터 유출 및 웹 애플리케이션 공격 위험',
            'recommendation': 'S3 버킷 공개 설정을 검토하고 WAF를 설정하세요.'
        })
    
    # 2. 보안 패턴 분석
    total_high_risk = sum(len([i for i in result.get('issues', []) if i.get('risk_level') == 'high']) 
                         for result in scan_results.values() if isinstance(result, dict) and 'issues' in result)
    
    if total_high_risk > 10:
        analysis['security_patterns'].append({
            'pattern': 'high_risk_concentration',
            'description': f'높은 위험도 이슈가 {total_high_risk}개로 집중됨',
            'recommendation': '높은 위험도 이슈를 우선적으로 해결하세요.'
        })
    
    # 3. 전체 보안 태세 평가
    if len(analysis['critical_gaps']) > 2:
        analysis['overall_posture'] = 'poor'
    elif len(analysis['critical_gaps']) > 0 or total_high_risk > 5:
        analysis['overall_posture'] = 'needs_improvement'
    elif total_high_risk == 0:
        analysis['overall_posture'] = 'good'
    else:
        analysis['overall_posture'] = 'fair'
    
    return analysis

def categorize_security_issue(issue, service):
    """보안 이슈를 카테고리별로 분류"""
    
    issue_type = issue.get('type', '').lower()
    
    # 접근 제어 관련
    if any(keyword in issue_type for keyword in ['iam', 'mfa', 'access', 'permission', 'policy', 'user', 'role']):
        return 'access_control'
    
    # 데이터 보호 관련
    elif any(keyword in issue_type for keyword in ['s3', 'encryption', 'bucket', 'public', 'data']):
        return 'data_protection'
    
    # 모니터링 관련
    elif any(keyword in issue_type for keyword in ['cloudtrail', 'logging', 'monitoring']):
        return 'monitoring'
    
    # 네트워크 보안 관련
    elif any(keyword in issue_type for keyword in ['waf', 'network', 'firewall', 'ip']):
        return 'network_security'
    
    # 위협 탐지 관련
    elif any(keyword in issue_type for keyword in ['guardduty', 'malware', 'threat', 'suspicious']):
        return 'threat_detection'
    
    # 규정 준수 관련
    else:
        return 'compliance'

def calculate_security_score(high_risk, medium_risk, low_risk, scan_results):
    """보안 점수 계산 (0-100)"""
    
    # 기본 점수 100에서 시작
    score = 100
    
    # 위험도별 점수 차감
    score -= high_risk * 15  # 높은 위험: 15점씩 차감
    score -= medium_risk * 5  # 중간 위험: 5점씩 차감
    score -= low_risk * 1     # 낮은 위험: 1점씩 차감
    
    # 서비스별 가중치 적용
    service_weights = {
        'iam': 1.5,      # IAM은 가장 중요
        'cloudtrail': 1.3,
        's3': 1.2,
        'guardduty': 1.1,
        'waf': 1.0
    }
    
    # 실패한 서비스에 대한 추가 차감
    for service, result in scan_results.items():
        if service == 'summary':
            continue
        if result.get('status') == 'failed':
            score -= 10 * service_weights.get(service, 1.0)
    
    # 점수 범위 제한 (0-100)
    return max(0, min(100, int(score)))

def get_priority_issues(scan_results):
    """우선순위 이슈 선별"""
    
    all_issues = []
    
    # 모든 이슈 수집
    for service, result in scan_results.items():
        if service == 'summary':
            continue
        
        for issue in result.get('issues', []):
            issue_with_service = issue.copy()
            issue_with_service['service'] = service
            all_issues.append(issue_with_service)
    
    # 심각도 점수 기준으로 정렬
    all_issues.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
    
    # 상위 10개 반환
    return all_issues[:10]

def evaluate_service_health(scan_results):
    """서비스별 보안 상태 평가"""
    
    health_status = {}
    
    for service in ['iam', 'cloudtrail', 's3', 'guardduty', 'waf']:
        result = scan_results.get(service, {})
        
        if result.get('status') == 'failed':
            health_status[service] = 'error'
        else:
            issues = result.get('issues', [])
            high_issues = len([i for i in issues if i.get('risk_level') == 'high'])
            medium_issues = len([i for i in issues if i.get('risk_level') == 'medium'])
            
            if high_issues > 3:
                health_status[service] = 'critical'
            elif high_issues > 0 or medium_issues > 5:
                health_status[service] = 'warning'
            elif medium_issues > 0:
                health_status[service] = 'caution'
            else:
                health_status[service] = 'healthy'
    
    return health_status

def evaluate_compliance_status(scan_results):
    """규정 준수 상태 평가"""
    
    compliance_checks = {
        'aws_foundational_security': {
            'name': 'AWS Foundational Security Standard',
            'passed': 0,
            'failed': 0,
            'total': 0
        },
        'cis_aws_foundations': {
            'name': 'CIS AWS Foundations Benchmark',
            'passed': 0,
            'failed': 0,
            'total': 0
        },
        'pci_dss': {
            'name': 'PCI DSS',
            'passed': 0,
            'failed': 0,
            'total': 0
        }
    }
    
    # 각 이슈를 규정 준수 기준에 매핑
    for service, result in scan_results.items():
        if service == 'summary':
            continue
        
        for issue in result.get('issues', []):
            issue_type = issue.get('type', '')
            
            # AWS Foundational Security Standard 체크
            if any(check in issue_type for check in ['mfa', 'root', 'encryption', 'public', 'logging']):
                compliance_checks['aws_foundational_security']['total'] += 1
                if issue.get('risk_level') in ['high', 'medium']:
                    compliance_checks['aws_foundational_security']['failed'] += 1
                else:
                    compliance_checks['aws_foundational_security']['passed'] += 1
            
            # CIS AWS Foundations Benchmark 체크
            if any(check in issue_type for check in ['cloudtrail', 'mfa', 'root', 'password_policy']):
                compliance_checks['cis_aws_foundations']['total'] += 1
                if issue.get('risk_level') in ['high', 'medium']:
                    compliance_checks['cis_aws_foundations']['failed'] += 1
                else:
                    compliance_checks['cis_aws_foundations']['passed'] += 1
            
            # PCI DSS 체크
            if any(check in issue_type for check in ['encryption', 'access', 'monitoring', 'waf']):
                compliance_checks['pci_dss']['total'] += 1
                if issue.get('risk_level') in ['high', 'medium']:
                    compliance_checks['pci_dss']['failed'] += 1
                else:
                    compliance_checks['pci_dss']['passed'] += 1
    
    return compliance_checks

def generate_integrated_recommendations(scan_results, integrated_analysis):
    """통합 권장 사항 생성"""
    
    recommendations = []
    
    # 중요한 보안 격차에 대한 권장사항
    for gap in integrated_analysis.get('critical_gaps', []):
        recommendations.append({
            'priority': 'critical',
            'category': 'security_gap',
            'title': gap['description'],
            'action': gap['recommendation'],
            'impact': gap['impact']
        })
    
    # 전체 보안 태세에 따른 권장사항
    posture = integrated_analysis.get('overall_posture', 'unknown')
    
    if posture == 'poor':
        recommendations.append({
            'priority': 'high',
            'category': 'overall_security',
            'title': '전체적인 보안 태세 개선 필요',
            'action': '보안 전문가와 상담하여 종합적인 보안 전략을 수립하세요.',
            'impact': '전체 AWS 환경의 보안 수준 향상'
        })
    
    # 서비스별 우선순위 권장사항
    service_priorities = {
        'iam': '신원 및 액세스 관리 강화',
        'cloudtrail': '활동 모니터링 및 로깅 개선',
        's3': '데이터 보호 및 액세스 제어',
        'guardduty': '위협 탐지 및 대응 체계 구축',
        'waf': '웹 애플리케이션 보안 강화'
    }
    
    for service, title in service_priorities.items():
        result = scan_results.get(service, {})
        high_issues = len([i for i in result.get('issues', []) if i.get('risk_level') == 'high'])
        
        if high_issues > 0:
            recommendations.append({
                'priority': 'high',
                'category': 'service_specific',
                'title': f'{title} ({high_issues}개 높은 위험 이슈)',
                'action': f'{service.upper()} 서비스의 높은 위험 이슈를 우선 해결하세요.',
                'impact': f'{service.upper()} 보안 수준 향상'
            })
    
    return recommendations[:10]  # 상위 10개 권장사항만 반환

def get_detailed_remediation_steps(issue_type, resource=None):
    """보안 이슈 유형별 상세한 해결 단계 제공"""
    
    remediation_templates = {
        # IAM 관련 이슈
        'mfa_not_enabled': {
            'title': 'MFA(다중 인증) 설정',
            'urgency': 'high',
            'estimated_time': '10-15분',
            'difficulty': 'easy',
            'steps': [
                '1. AWS 콘솔에 로그인하여 IAM 서비스로 이동',
                '2. 좌측 메뉴에서 "사용자" 선택',
                f'3. 해당 사용자({resource or "[사용자명]"}) 클릭',
                '4. "보안 자격 증명" 탭 선택',
                '5. "할당된 MFA 디바이스" 섹션에서 "관리" 클릭',
                '6. MFA 디바이스 유형 선택 (가상 MFA 디바이스 권장)',
                '7. 모바일 앱(Google Authenticator, Authy 등)으로 QR 코드 스캔',
                '8. 연속된 두 개의 MFA 코드 입력하여 설정 완료'
            ],
            'verification': [
                '사용자 상세 페이지에서 "할당된 MFA 디바이스" 확인',
                '다음 로그인 시 MFA 코드 요구 확인'
            ],
            'aws_docs': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html',
            'cost_impact': '무료',
            'security_impact': '계정 탈취 위험 대폭 감소'
        },
        
        'root_access_keys': {
            'title': '루트 계정 액세스 키 삭제',
            'urgency': 'critical',
            'estimated_time': '5-10분',
            'difficulty': 'easy',
            'steps': [
                '1. 루트 계정으로 AWS 콘솔 로그인',
                '2. 우측 상단 계정명 클릭 → "보안 자격 증명" 선택',
                '3. "액세스 키" 섹션 확장',
                '4. 기존 액세스 키의 "작업" → "삭제" 선택',
                '5. 삭제 확인 후 완료',
                '6. 필요시 IAM 사용자 생성하여 프로그래밍 방식 액세스 대체'
            ],
            'verification': [
                '보안 자격 증명 페이지에서 "액세스 키 없음" 확인',
                'AWS CLI/SDK 사용 시 IAM 사용자 자격 증명으로 전환 확인'
            ],
            'aws_docs': 'https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html',
            'cost_impact': '무료',
            'security_impact': '루트 계정 보안 대폭 강화'
        },
        
        'old_access_key': {
            'title': '오래된 액세스 키 교체',
            'urgency': 'medium',
            'estimated_time': '15-20분',
            'difficulty': 'medium',
            'steps': [
                '1. IAM 콘솔에서 해당 사용자 선택',
                '2. "보안 자격 증명" 탭에서 새 액세스 키 생성',
                '3. 새 액세스 키 정보를 안전한 곳에 저장',
                '4. 애플리케이션/스크립트에서 새 액세스 키로 업데이트',
                '5. 새 키로 정상 작동 확인 후 기존 키를 "비활성" 상태로 변경',
                '6. 24-48시간 모니터링 후 문제없으면 기존 키 삭제'
            ],
            'verification': [
                '새 액세스 키로 AWS API 호출 정상 작동 확인',
                '기존 키 삭제 후 애플리케이션 오류 없음 확인'
            ],
            'aws_docs': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey',
            'cost_impact': '무료',
            'security_impact': '액세스 키 탈취 위험 감소'
        },
        
        # CloudTrail 관련 이슈
        'no_cloudtrail': {
            'title': 'CloudTrail 활성화',
            'urgency': 'high',
            'estimated_time': '10-15분',
            'difficulty': 'easy',
            'steps': [
                '1. AWS 콘솔에서 CloudTrail 서비스로 이동',
                '2. "트레일 생성" 버튼 클릭',
                '3. 트레일 이름 입력 (예: "main-cloudtrail")',
                '4. "모든 리전에 적용" 옵션 활성화',
                '5. S3 버킷 설정 (새 버킷 생성 또는 기존 버킷 선택)',
                '6. "로그 파일 검증 활성화" 체크',
                '7. "글로벌 서비스 이벤트 포함" 체크',
                '8. "트레일 생성" 클릭하여 완료'
            ],
            'verification': [
                'CloudTrail 콘솔에서 트레일 상태 "로깅" 확인',
                'S3 버킷에 로그 파일 생성 확인 (몇 분 후)'
            ],
            'aws_docs': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html',
            'cost_impact': 'S3 스토리지 비용 발생 (월 $1-5 예상)',
            'security_impact': 'API 활동 모니터링 및 감사 기능 확보'
        },
        
        # S3 관련 이슈
        'public_bucket_policy': {
            'title': 'S3 버킷 공개 정책 수정',
            'urgency': 'critical',
            'estimated_time': '5-10분',
            'difficulty': 'medium',
            'steps': [
                '1. S3 콘솔에서 해당 버킷 선택',
                '2. "권한" 탭 클릭',
                '3. "버킷 정책" 섹션에서 "편집" 클릭',
                '4. 정책에서 "Principal": "*" 부분 확인',
                '5. 필요한 경우 특정 IP 또는 계정으로 제한',
                '6. 불필요한 공개 액세스인 경우 해당 정책 삭제',
                '7. "변경 사항 저장" 클릭',
                '8. "퍼블릭 액세스 차단" 설정도 함께 검토'
            ],
            'verification': [
                'S3 콘솔에서 버킷 "퍼블릭" 표시 사라짐 확인',
                '외부에서 버킷 접근 불가 확인'
            ],
            'aws_docs': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
            'cost_impact': '무료',
            'security_impact': '데이터 유출 위험 제거'
        },
        
        'bucket_not_encrypted': {
            'title': 'S3 버킷 암호화 설정',
            'urgency': 'medium',
            'estimated_time': '5분',
            'difficulty': 'easy',
            'steps': [
                '1. S3 콘솔에서 해당 버킷 선택',
                '2. "속성" 탭 클릭',
                '3. "기본 암호화" 섹션에서 "편집" 클릭',
                '4. "서버 측 암호화" 활성화',
                '5. 암호화 유형 선택:',
                '   - SSE-S3: AWS 관리형 키 (권장)',
                '   - SSE-KMS: AWS KMS 키 (고급 제어 필요시)',
                '6. "변경 사항 저장" 클릭'
            ],
            'verification': [
                '버킷 속성에서 "기본 암호화" 활성화 확인',
                '새로 업로드되는 객체 암호화 적용 확인'
            ],
            'aws_docs': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html',
            'cost_impact': 'SSE-S3: 무료, SSE-KMS: KMS 키 사용료',
            'security_impact': '저장 데이터 보호 강화'
        },
        
        # GuardDuty 관련 이슈
        'guardduty_not_enabled': {
            'title': 'GuardDuty 활성화',
            'urgency': 'high',
            'estimated_time': '5분',
            'difficulty': 'easy',
            'steps': [
                '1. AWS 콘솔에서 GuardDuty 서비스로 이동',
                '2. "GuardDuty 시작하기" 클릭',
                '3. 서비스 역할 권한 검토 후 "GuardDuty 활성화" 클릭',
                '4. 추가 데이터 소스 설정:',
                '   - S3 보호: 활성화 권장',
                '   - 악성코드 보호: 활성화 권장',
                '   - Kubernetes 보호: EKS 사용시 활성화',
                '5. 알림 설정 (SNS 토픽 연결 권장)'
            ],
            'verification': [
                'GuardDuty 콘솔에서 "활성" 상태 확인',
                '발견 사항 페이지 접근 가능 확인'
            ],
            'aws_docs': 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html',
            'cost_impact': '월 $1-10 (사용량에 따라)',
            'security_impact': '위협 탐지 및 보안 모니터링 확보'
        },
        
        # WAF 관련 이슈
        'no_waf_configured': {
            'title': 'WAF 설정',
            'urgency': 'medium',
            'estimated_time': '20-30분',
            'difficulty': 'medium',
            'steps': [
                '1. AWS 콘솔에서 WAF & Shield 서비스로 이동',
                '2. "Web ACL 생성" 클릭',
                '3. 리소스 유형 선택 (CloudFront/ALB/API Gateway)',
                '4. Web ACL 이름 및 설명 입력',
                '5. 관리형 규칙 그룹 추가:',
                '   - AWS Core Rule Set (필수)',
                '   - AWS Known Bad Inputs',
                '   - OWASP Top 10 (웹앱의 경우)',
                '6. Rate limiting 규칙 추가 (예: 2000 req/5min)',
                '7. 기본 액션을 "허용"으로 설정',
                '8. Web ACL을 대상 리소스에 연결'
            ],
            'verification': [
                'WAF 콘솔에서 Web ACL 활성 상태 확인',
                '연결된 리소스에서 WAF 적용 확인',
                '테스트 요청으로 규칙 작동 확인'
            ],
            'aws_docs': 'https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html',
            'cost_impact': '월 $5-20 (규칙 수와 요청량에 따라)',
            'security_impact': '웹 애플리케이션 공격 차단'
        }
    }
    
    return remediation_templates.get(issue_type, {
        'title': '보안 이슈 해결',
        'urgency': 'medium',
        'estimated_time': '시간 미정',
        'difficulty': 'medium',
        'steps': ['해당 이슈에 대한 AWS 문서를 참조하여 해결하세요.'],
        'verification': ['설정 변경 후 보안 상태를 다시 확인하세요.'],
        'aws_docs': 'https://docs.aws.amazon.com/',
        'cost_impact': '비용 영향 검토 필요',
        'security_impact': '보안 수준 향상'
    })

def generate_remediation_plan(issues, max_issues=20):
    """이슈 목록을 기반으로 종합적인 해결 계획 생성"""
    
    plan = {
        'immediate_actions': [],  # 즉시 조치 (Critical/High)
        'short_term_actions': [], # 단기 조치 (Medium)
        'long_term_actions': [],  # 장기 조치 (Low)
        'estimated_total_time': 0,
        'estimated_cost_impact': 'TBD',
        'priority_order': []
    }
    
    # 이슈를 우선순위별로 분류
    for issue in issues[:max_issues]:
        remediation = get_detailed_remediation_steps(issue.get('type'), issue.get('resource'))
        
        action_item = {
            'issue': issue,
            'remediation': remediation,
            'service': issue.get('service', 'unknown')
        }
        
        urgency = remediation.get('urgency', 'medium')
        
        if urgency in ['critical', 'high']:
            plan['immediate_actions'].append(action_item)
        elif urgency == 'medium':
            plan['short_term_actions'].append(action_item)
        else:
            plan['long_term_actions'].append(action_item)
        
        # 예상 시간 계산 (분 단위)
        time_str = remediation.get('estimated_time', '10분')
        try:
            if '분' in time_str:
                time_parts = time_str.split('-')
                if len(time_parts) == 2:
                    avg_time = (int(time_parts[0]) + int(time_parts[1].replace('분', ''))) / 2
                else:
                    avg_time = int(time_str.replace('분', ''))
                plan['estimated_total_time'] += avg_time
        except:
            plan['estimated_total_time'] += 15  # 기본값
    
    # 우선순위 순서 생성
    all_actions = plan['immediate_actions'] + plan['short_term_actions'] + plan['long_term_actions']
    plan['priority_order'] = [action['issue']['type'] for action in all_actions]
    
    # 총 예상 시간을 시간 단위로 변환
    total_hours = plan['estimated_total_time'] / 60
    if total_hours < 1:
        plan['estimated_total_time_display'] = f"{int(plan['estimated_total_time'])}분"
    else:
        plan['estimated_total_time_display'] = f"{total_hours:.1f}시간"
    
    return plan

def get_aws_documentation_links():
    """AWS 보안 관련 주요 문서 링크 모음"""
    
    return {
        'security_best_practices': {
            'title': 'AWS 보안 모범 사례',
            'url': 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html',
            'description': 'AWS Well-Architected 보안 원칙'
        },
        'iam_best_practices': {
            'title': 'IAM 모범 사례',
            'url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
            'description': 'IAM 사용자, 역할, 정책 관리 가이드'
        },
        'cloudtrail_guide': {
            'title': 'CloudTrail 사용자 가이드',
            'url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/',
            'description': 'API 활동 로깅 및 모니터링'
        },
        's3_security': {
            'title': 'S3 보안 모범 사례',
            'url': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html',
            'description': 'S3 버킷 및 객체 보안 설정'
        },
        'guardduty_guide': {
            'title': 'GuardDuty 사용자 가이드',
            'url': 'https://docs.aws.amazon.com/guardduty/latest/ug/',
            'description': '위협 탐지 및 보안 모니터링'
        },
        'waf_guide': {
            'title': 'WAF 개발자 가이드',
            'url': 'https://docs.aws.amazon.com/waf/latest/developerguide/',
            'description': '웹 애플리케이션 방화벽 설정'
        },
        'security_hub': {
            'title': 'AWS Security Hub',
            'url': 'https://docs.aws.amazon.com/securityhub/latest/userguide/',
            'description': '중앙 집중식 보안 관리'
        },
        'config_rules': {
            'title': 'AWS Config 규칙',
            'url': 'https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html',
            'description': '리소스 구성 규정 준수 모니터링'
        }
    }

def get_amazon_q_recommendations(issue, context=None):
    """Amazon Q 기반 맞춤형 권장 사항 생성 (선택사항)"""
    
    try:
        # Amazon Q API 연동 시도 (실제 구현에서는 boto3 사용)
        # 현재는 시뮬레이션으로 구현
        
        issue_type = issue.get('type', '')
        service = issue.get('service', '')
        resource = issue.get('resource', '')
        
        # Amazon Q 스타일의 맞춤형 권장사항 생성
        q_recommendations = {
            'mfa_not_enabled': {
                'ai_analysis': f"사용자 {resource}에 대한 MFA 미설정은 계정 탈취의 주요 위험 요소입니다.",
                'contextual_advice': "현재 환경에서는 가상 MFA 디바이스 사용을 권장합니다.",
                'automation_suggestion': "AWS CLI를 사용한 일괄 MFA 설정 스크립트를 제공할 수 있습니다.",
                'related_services': ["AWS IAM Identity Center", "AWS Organizations SCPs"],
                'compliance_impact': "SOC 2, ISO 27001 규정 준수에 필수적입니다."
            },
            'public_bucket_policy': {
                'ai_analysis': f"S3 버킷 {resource}의 공개 정책은 데이터 유출의 직접적인 위험을 초래합니다.",
                'contextual_advice': "CloudFront를 통한 제한적 공개 액세스를 고려해보세요.",
                'automation_suggestion': "S3 버킷 정책 자동 검증 Lambda 함수 설정을 권장합니다.",
                'related_services': ["AWS Config", "AWS CloudTrail", "AWS Macie"],
                'compliance_impact': "GDPR, CCPA 등 데이터 보호 규정 위반 가능성이 있습니다."
            },
            'no_cloudtrail': {
                'ai_analysis': "CloudTrail 미설정은 보안 사고 발생 시 원인 분석을 불가능하게 만듭니다.",
                'contextual_advice': "멀티 리전 트레일 설정으로 전체 AWS 환경을 모니터링하세요.",
                'automation_suggestion': "CloudFormation 템플릿을 사용한 표준화된 CloudTrail 설정을 제공합니다.",
                'related_services': ["AWS CloudWatch", "AWS EventBridge", "AWS Security Hub"],
                'compliance_impact': "PCI DSS, HIPAA 등 규정에서 요구하는 감사 로그 요구사항을 충족하지 못합니다."
            }
        }
        
        base_recommendation = q_recommendations.get(issue_type, {
            'ai_analysis': f"{service} 서비스의 {issue_type} 이슈는 보안 위험을 증가시킵니다.",
            'contextual_advice': "AWS 보안 모범 사례를 따라 해결하세요.",
            'automation_suggestion': "AWS Config 규칙을 사용한 자동 모니터링을 고려하세요.",
            'related_services': ["AWS Security Hub", "AWS Config"],
            'compliance_impact': "조직의 보안 정책 및 규정 준수 요구사항을 검토하세요."
        })
        
        # 컨텍스트 기반 추가 권장사항
        if context:
            account_info = context.get('account_info', {})
            scan_results = context.get('scan_results', {})
            
            # 계정 크기에 따른 권장사항 조정
            total_issues = sum(len(result.get('issues', [])) for result in scan_results.values() 
                             if isinstance(result, dict) and 'issues' in result)
            
            if total_issues > 20:
                base_recommendation['scale_advice'] = "대규모 환경으로 보이므로 AWS Organizations와 AWS Control Tower 사용을 권장합니다."
            
            # 리전 기반 권장사항
            region = account_info.get('region', '')
            if region == 'ap-northeast-2':
                base_recommendation['regional_advice'] = "한국 리전 사용자를 위한 한국어 AWS 지원 및 문서를 활용하세요."
        
        return {
            'available': True,
            'recommendations': base_recommendation,
            'confidence_score': 0.85,
            'generated_at': datetime.now().isoformat()
        }
        
    except Exception as e:
        # Amazon Q API 사용 불가능한 경우 기본 권장사항 반환
        return {
            'available': False,
            'error': str(e),
            'fallback_message': "Amazon Q 서비스를 사용할 수 없습니다. 기본 권장사항을 사용합니다."
        }

def enhance_recommendations_with_ai(issues, context=None):
    """AI 기반으로 권장사항 향상"""
    
    enhanced_recommendations = []
    
    for issue in issues[:10]:  # 상위 10개 이슈만 처리
        base_remediation = get_detailed_remediation_steps(issue.get('type'), issue.get('resource'))
        
        # Amazon Q 권장사항 시도
        q_recommendation = get_amazon_q_recommendations(issue, context)
        
        enhanced_item = {
            'issue': issue,
            'base_remediation': base_remediation,
            'ai_enhanced': q_recommendation.get('available', False)
        }
        
        if q_recommendation.get('available'):
            enhanced_item['ai_recommendations'] = q_recommendation['recommendations']
            enhanced_item['confidence_score'] = q_recommendation.get('confidence_score', 0.0)
        else:
            enhanced_item['ai_fallback'] = q_recommendation.get('fallback_message', '')
        
        enhanced_recommendations.append(enhanced_item)
    
    return enhanced_recommendations

def generate_executive_summary(scan_results, integrated_analysis):
    """경영진을 위한 요약 보고서 생성"""
    
    summary = integrated_analysis.get('summary', {})
    
    # 보안 점수 및 전체 상태
    security_score = summary.get('security_score', 0)
    total_issues = summary.get('total_issues', 0)
    high_risk_issues = summary.get('high_risk', 0)
    
    # 위험도 평가
    if security_score >= 90:
        risk_level = "낮음"
        risk_color = "green"
    elif security_score >= 70:
        risk_level = "보통"
        risk_color = "yellow"
    elif security_score >= 50:
        risk_level = "높음"
        risk_color = "orange"
    else:
        risk_level = "매우 높음"
        risk_color = "red"
    
    # 주요 발견사항
    key_findings = []
    critical_gaps = integrated_analysis.get('critical_gaps', [])
    
    for gap in critical_gaps[:3]:  # 상위 3개만
        key_findings.append({
            'title': gap.get('description', ''),
            'impact': gap.get('impact', ''),
            'severity': gap.get('severity', 'medium')
        })
    
    # 비즈니스 영향 평가
    business_impact = {
        'data_breach_risk': "높음" if high_risk_issues > 5 else "보통" if high_risk_issues > 0 else "낮음",
        'compliance_risk': "높음" if any('compliance' in str(gap) for gap in critical_gaps) else "보통",
        'operational_risk': "보통" if total_issues > 10 else "낮음",
        'reputation_risk': "높음" if any('public' in str(issue) for result in scan_results.values() 
                                      if isinstance(result, dict) 
                                      for issue in result.get('issues', [])) else "보통"
    }
    
    # 권장 조치 우선순위
    priority_actions = [
        "높은 위험도 보안 이슈 즉시 해결",
        "CloudTrail 및 GuardDuty 활성화로 모니터링 강화",
        "IAM 정책 검토 및 MFA 의무화",
        "S3 버킷 공개 설정 전면 검토",
        "정기적인 보안 점검 체계 구축"
    ]
    
    return {
        'security_score': security_score,
        'risk_level': risk_level,
        'risk_color': risk_color,
        'total_issues': total_issues,
        'high_risk_issues': high_risk_issues,
        'key_findings': key_findings,
        'business_impact': business_impact,
        'priority_actions': priority_actions[:3],  # 상위 3개만
        'estimated_resolution_time': f"{(total_issues * 15) // 60}시간",
        'recommended_budget': "월 $50-200 (보안 서비스 활성화 기준)"
    }

# 개별 스캔 함수들
def perform_iam_scan(aws_session, deep_scan=False):
    """IAM 리소스 스캔 수행"""
    
    try:
        iam_client = aws_session.client('iam')
        
        # IAM 데이터 수집
        iam_data = {
            'users': [],
            'roles': [],
            'groups': [],
            'policies': [],
            'account_summary': {}
        }
        
        issues = []
        
        # 1. 계정 요약 정보 수집
        try:
            account_summary = iam_client.get_account_summary()
            iam_data['account_summary'] = account_summary.get('SummaryMap', {})
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                raise e
        
        # 2. IAM 사용자 목록 조회 및 상태 정보 수집
        try:
            users_response = iam_client.list_users()
            users = users_response.get('Users', [])
            
            for user in users:
                user_name = user['UserName']
                user_info = {
                    'name': user_name,
                    'arn': user['Arn'],
                    'created_date': user['CreateDate'],
                    'password_last_used': user.get('PasswordLastUsed'),
                    'mfa_enabled': False,
                    'access_keys': [],
                    'attached_policies': [],
                    'groups': []
                }
                
                # MFA 디바이스 확인
                try:
                    mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
                    user_info['mfa_enabled'] = len(mfa_devices.get('MFADevices', [])) > 0
                    
                    if not user_info['mfa_enabled']:
                        issues.append({
                            'type': 'mfa_not_enabled',
                            'risk_level': 'high',
                            'resource': user_name,
                            'description': f'사용자 {user_name}에 MFA가 설정되지 않음',
                            'recommendation': 'IAM 콘솔에서 MFA 디바이스를 설정하세요.'
                        })
                except ClientError:
                    pass
                
                # 액세스 키 정보 수집
                try:
                    access_keys = iam_client.list_access_keys(UserName=user_name)
                    for key in access_keys.get('AccessKeyMetadata', []):
                        key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                        user_info['access_keys'].append({
                            'access_key_id': key['AccessKeyId'],
                            'status': key['Status'],
                            'created_date': key['CreateDate'],
                            'age_days': key_age
                        })
                        
                        # 오래된 액세스 키 검사
                        if key_age > 90:
                            issues.append({
                                'type': 'old_access_key',
                                'risk_level': 'medium',
                                'resource': f"{user_name}:{key['AccessKeyId'][:8]}...",
                                'description': f'사용자 {user_name}의 액세스 키가 {key_age}일 동안 사용됨',
                                'recommendation': '정기적으로 액세스 키를 교체하세요.'
                            })
                except ClientError:
                    pass
                
                # 사용자 정책 정보 수집
                try:
                    attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
                    user_info['attached_policies'] = [
                        {
                            'policy_name': policy['PolicyName'],
                            'policy_arn': policy['PolicyArn']
                        }
                        for policy in attached_policies.get('AttachedPolicies', [])
                    ]
                    
                    # 관리자 권한 검사
                    for policy in attached_policies.get('AttachedPolicies', []):
                        if 'AdministratorAccess' in policy['PolicyName']:
                            issues.append({
                                'type': 'admin_access',
                                'risk_level': 'high',
                                'resource': user_name,
                                'description': f'사용자 {user_name}에 관리자 권한이 부여됨',
                                'recommendation': '최소 권한 원칙에 따라 필요한 권한만 부여하세요.'
                            })
                except ClientError:
                    pass
                
                # 사용자 그룹 정보 수집
                try:
                    groups_for_user = iam_client.get_groups_for_user(UserName=user_name)
                    user_info['groups'] = [group['GroupName'] for group in groups_for_user.get('Groups', [])]
                except ClientError:
                    pass
                
                iam_data['users'].append(user_info)
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                raise e
        
        # 3. IAM 역할 목록 조회 및 정책 정보 수집
        try:
            roles_response = iam_client.list_roles()
            roles = roles_response.get('Roles', [])
            
            for role in roles:
                role_name = role['RoleName']
                role_info = {
                    'name': role_name,
                    'arn': role['Arn'],
                    'created_date': role['CreateDate'],
                    'assume_role_policy': role.get('AssumeRolePolicyDocument'),
                    'attached_policies': [],
                    'last_used': None
                }
                
                # 역할 정책 정보 수집
                try:
                    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                    role_info['attached_policies'] = [
                        {
                            'policy_name': policy['PolicyName'],
                            'policy_arn': policy['PolicyArn']
                        }
                        for policy in attached_policies.get('AttachedPolicies', [])
                    ]
                    
                    # 과도한 권한 검사
                    for policy in attached_policies.get('AttachedPolicies', []):
                        if any(admin_policy in policy['PolicyName'] for admin_policy in ['AdministratorAccess', 'PowerUserAccess']):
                            issues.append({
                                'type': 'excessive_role_permissions',
                                'risk_level': 'medium',
                                'resource': role_name,
                                'description': f'역할 {role_name}에 과도한 권한이 부여됨',
                                'recommendation': '역할의 권한을 검토하고 필요한 권한만 부여하세요.'
                            })
                except ClientError:
                    pass
                
                # 역할 사용 이력 확인 (deep_scan인 경우)
                if deep_scan:
                    try:
                        role_usage = iam_client.get_role(RoleName=role_name)
                        role_info['last_used'] = role_usage.get('Role', {}).get('RoleLastUsed')
                    except ClientError:
                        pass
                
                iam_data['roles'].append(role_info)
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                raise e
        
        # 4. IAM 그룹 목록 조회 및 멤버 정보 수집
        try:
            groups_response = iam_client.list_groups()
            groups = groups_response.get('Groups', [])
            
            for group in groups:
                group_name = group['GroupName']
                group_info = {
                    'name': group_name,
                    'arn': group['Arn'],
                    'created_date': group['CreateDate'],
                    'attached_policies': [],
                    'members': []
                }
                
                # 그룹 정책 정보 수집
                try:
                    attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
                    group_info['attached_policies'] = [
                        {
                            'policy_name': policy['PolicyName'],
                            'policy_arn': policy['PolicyArn']
                        }
                        for policy in attached_policies.get('AttachedPolicies', [])
                    ]
                except ClientError:
                    pass
                
                # 그룹 멤버 정보 수집
                try:
                    group_users = iam_client.get_group(GroupName=group_name)
                    group_info['members'] = [user['UserName'] for user in group_users.get('Users', [])]
                except ClientError:
                    pass
                
                iam_data['groups'].append(group_info)
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                raise e
        
        # 5. 추가 보안 위험 탐지
        additional_issues = detect_iam_security_risks(iam_data, deep_scan)
        issues.extend(additional_issues)
        
        return {
            'data': {
                'users_count': len(iam_data['users']),
                'roles_count': len(iam_data['roles']),
                'groups_count': len(iam_data['groups']),
                'users': iam_data['users'],
                'roles': iam_data['roles'],
                'groups': iam_data['groups'],
                'account_summary': iam_data['account_summary']
            },
            'issues': issues
        }
        
    except Exception as e:
        # IAM 스캔 실패 시 기본 정보 반환
        return {
            'data': {
                'users_count': 0,
                'roles_count': 0,
                'groups_count': 0,
                'error': str(e)
            },
            'issues': [{
                'type': 'scan_error',
                'risk_level': 'medium',
                'resource': 'IAM Service',
                'description': f'IAM 스캔 중 오류 발생: {str(e)}',
                'recommendation': 'IAM 읽기 권한을 확인하고 다시 시도하세요.'
            }]
        }

def detect_iam_security_risks(iam_data, deep_scan=False):
    """IAM 보안 위험 요소 탐지"""
    
    issues = []
    
    # 1. 루트 계정 보안 검사
    account_summary = iam_data.get('account_summary', {})
    
    # 루트 계정 액세스 키 존재 검사
    if account_summary.get('AccountAccessKeysPresent', 0) > 0:
        issues.append({
            'type': 'root_access_keys',
            'risk_level': 'high',
            'resource': 'Root Account',
            'description': '루트 계정에 액세스 키가 존재함',
            'recommendation': '루트 계정의 액세스 키를 즉시 삭제하고 IAM 사용자를 사용하세요.',
            'severity_score': 9.0
        })
    
    # 루트 계정 MFA 미설정 검사
    if account_summary.get('AccountMFAEnabled', 0) == 0:
        issues.append({
            'type': 'root_mfa_not_enabled',
            'risk_level': 'high',
            'resource': 'Root Account',
            'description': '루트 계정에 MFA가 설정되지 않음',
            'recommendation': '루트 계정에 MFA를 즉시 설정하세요.',
            'severity_score': 8.5
        })
    
    # 2. 사용자 보안 위험 검사
    users = iam_data.get('users', [])
    
    for user in users:
        user_name = user['name']
        
        # 비활성 사용자 검사
        if user.get('password_last_used'):
            last_used = user['password_last_used']
            if isinstance(last_used, str):
                try:
                    last_used = datetime.fromisoformat(last_used.replace('Z', '+00:00'))
                except:
                    last_used = datetime.now() - timedelta(days=1)  # 파싱 실패 시 기본값
            
            days_inactive = (datetime.now(last_used.tzinfo) - last_used).days
            
            if days_inactive > 90:
                risk_level = 'medium' if days_inactive > 180 else 'low'
                issues.append({
                    'type': 'inactive_user',
                    'risk_level': risk_level,
                    'resource': user_name,
                    'description': f'사용자 {user_name}이 {days_inactive}일 동안 비활성 상태',
                    'recommendation': '사용하지 않는 사용자 계정을 비활성화하거나 삭제하세요.',
                    'severity_score': 3.0 if days_inactive > 180 else 2.0
                })
        
        # 액세스 키 보안 검사
        for access_key in user.get('access_keys', []):
            key_age = access_key.get('age_days', 0)
            
            # 매우 오래된 액세스 키
            if key_age > 365:
                issues.append({
                    'type': 'very_old_access_key',
                    'risk_level': 'high',
                    'resource': f"{user_name}:{access_key['access_key_id'][:8]}...",
                    'description': f'사용자 {user_name}의 액세스 키가 {key_age}일 동안 사용됨 (1년 초과)',
                    'recommendation': '액세스 키를 즉시 교체하세요.',
                    'severity_score': 7.0
                })
            elif key_age > 90:
                issues.append({
                    'type': 'old_access_key',
                    'risk_level': 'medium',
                    'resource': f"{user_name}:{access_key['access_key_id'][:8]}...",
                    'description': f'사용자 {user_name}의 액세스 키가 {key_age}일 동안 사용됨',
                    'recommendation': '정기적으로 액세스 키를 교체하세요.',
                    'severity_score': 4.0
                })
            
            # 비활성 액세스 키
            if access_key.get('status') == 'Inactive':
                issues.append({
                    'type': 'inactive_access_key',
                    'risk_level': 'low',
                    'resource': f"{user_name}:{access_key['access_key_id'][:8]}...",
                    'description': f'사용자 {user_name}에 비활성 액세스 키가 존재함',
                    'recommendation': '사용하지 않는 액세스 키를 삭제하세요.',
                    'severity_score': 2.0
                })
        
        # 과도한 권한 검사
        for policy in user.get('attached_policies', []):
            if any(admin_policy in policy['policy_name'] for admin_policy in 
                   ['AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess']):
                issues.append({
                    'type': 'excessive_user_permissions',
                    'risk_level': 'high',
                    'resource': user_name,
                    'description': f'사용자 {user_name}에 과도한 권한 ({policy["policy_name"]})이 부여됨',
                    'recommendation': '최소 권한 원칙에 따라 필요한 권한만 부여하세요.',
                    'severity_score': 8.0
                })
        
        # 다중 액세스 키 검사
        if len(user.get('access_keys', [])) > 1:
            issues.append({
                'type': 'multiple_access_keys',
                'risk_level': 'medium',
                'resource': user_name,
                'description': f'사용자 {user_name}에 여러 개의 액세스 키가 존재함',
                'recommendation': '불필요한 액세스 키를 삭제하고 하나만 유지하세요.',
                'severity_score': 4.5
            })
    
    # 3. 역할 보안 위험 검사
    roles = iam_data.get('roles', [])
    
    for role in roles:
        role_name = role['name']
        
        # 신뢰 정책 검사 (deep_scan인 경우)
        if deep_scan and role.get('assume_role_policy'):
            trust_policy = role['assume_role_policy']
            
            # 와일드카드 신뢰 정책 검사
            if '*' in str(trust_policy):
                issues.append({
                    'type': 'wildcard_trust_policy',
                    'risk_level': 'high',
                    'resource': role_name,
                    'description': f'역할 {role_name}의 신뢰 정책에 와일드카드(*)가 포함됨',
                    'recommendation': '신뢰 정책을 구체적인 주체로 제한하세요.',
                    'severity_score': 8.5
                })
        
        # 서비스 역할이 아닌 경우 외부 ID 검사
        if not any(service in role_name.lower() for service in ['service', 'lambda', 'ec2', 'ecs']):
            if role.get('assume_role_policy') and 'sts:ExternalId' not in str(role.get('assume_role_policy', '')):
                issues.append({
                    'type': 'missing_external_id',
                    'risk_level': 'medium',
                    'resource': role_name,
                    'description': f'크로스 계정 역할 {role_name}에 External ID가 설정되지 않음',
                    'recommendation': '크로스 계정 역할에는 External ID를 설정하세요.',
                    'severity_score': 5.0
                })
    
    # 4. 그룹 보안 위험 검사
    groups = iam_data.get('groups', [])
    
    for group in groups:
        group_name = group['name']
        
        # 빈 그룹 검사
        if len(group.get('members', [])) == 0:
            issues.append({
                'type': 'empty_group',
                'risk_level': 'low',
                'resource': group_name,
                'description': f'그룹 {group_name}에 멤버가 없음',
                'recommendation': '사용하지 않는 그룹을 삭제하세요.',
                'severity_score': 1.0
            })
        
        # 그룹의 과도한 권한 검사
        for policy in group.get('attached_policies', []):
            if 'AdministratorAccess' in policy['policy_name']:
                issues.append({
                    'type': 'group_admin_access',
                    'risk_level': 'high',
                    'resource': group_name,
                    'description': f'그룹 {group_name}에 관리자 권한이 부여됨',
                    'recommendation': '그룹 권한을 검토하고 최소 권한을 적용하세요.',
                    'severity_score': 7.5
                })
    
    # 5. 전체 계정 보안 정책 검사
    # 패스워드 정책 검사
    if account_summary.get('PasswordPolicy', 0) == 0:
        issues.append({
            'type': 'no_password_policy',
            'risk_level': 'medium',
            'resource': 'Account',
            'description': '계정에 패스워드 정책이 설정되지 않음',
            'recommendation': '강력한 패스워드 정책을 설정하세요.',
            'severity_score': 5.5
        })
    
    # 사용자 수 대비 MFA 활성화율 검사
    total_users = len(users)
    mfa_enabled_users = sum(1 for user in users if user.get('mfa_enabled', False))
    
    if total_users > 0:
        mfa_rate = mfa_enabled_users / total_users
        if mfa_rate < 0.8:  # 80% 미만
            issues.append({
                'type': 'low_mfa_adoption',
                'risk_level': 'medium',
                'resource': 'Account',
                'description': f'MFA 활성화율이 낮음 ({mfa_enabled_users}/{total_users}, {mfa_rate:.1%})',
                'recommendation': '모든 사용자에게 MFA 설정을 권장하세요.',
                'severity_score': 6.0
            })
    
    # 이슈를 심각도 순으로 정렬
    issues.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
    
    return issues

def analyze_suspicious_activities(events):
    """의심스러운 API 호출 패턴 분석"""
    
    issues = []
    
    if not events:
        return issues
    
    # 분석을 위한 데이터 구조 초기화
    ip_addresses = {}
    failed_logins = []
    unusual_activities = []
    high_risk_events = []
    user_activities = {}
    
    # 이벤트 분석
    for event in events:
        event_name = event.get('EventName', '')
        source_ip = event.get('SourceIPAddress', '')
        username = event.get('Username', '')
        event_time = event.get('EventTime')
        error_code = event.get('ErrorCode')
        aws_region = event.get('AwsRegion', '')
        user_agent = event.get('UserAgent', '')
        
        # IP 주소별 활동 집계
        if source_ip:
            if source_ip not in ip_addresses:
                ip_addresses[source_ip] = {'count': 0, 'events': [], 'users': set(), 'regions': set()}
            ip_addresses[source_ip]['count'] += 1
            ip_addresses[source_ip]['events'].append(event_name)
            ip_addresses[source_ip]['users'].add(username)
            ip_addresses[source_ip]['regions'].add(aws_region)
        
        # 사용자별 활동 집계
        if username:
            if username not in user_activities:
                user_activities[username] = {'count': 0, 'ips': set(), 'regions': set(), 'events': []}
            user_activities[username]['count'] += 1
            user_activities[username]['ips'].add(source_ip)
            user_activities[username]['regions'].add(aws_region)
            user_activities[username]['events'].append(event_name)
        
        # 실패한 로그인 시도 수집
        if error_code and 'SigninFailure' in event_name:
            failed_logins.append({
                'time': event_time,
                'ip': source_ip,
                'username': username,
                'error': error_code
            })
        
        # 고위험 이벤트 탐지
        high_risk_event_patterns = [
            'DeleteTrail', 'StopLogging', 'DeleteBucket', 'DeleteUser', 'DeleteRole',
            'AttachUserPolicy', 'AttachRolePolicy', 'CreateUser', 'CreateRole',
            'ModifyDBInstance', 'AuthorizeSecurityGroupIngress', 'CreateAccessKey'
        ]
        
        if any(pattern in event_name for pattern in high_risk_event_patterns):
            high_risk_events.append({
                'event_name': event_name,
                'username': username,
                'source_ip': source_ip,
                'time': event_time,
                'region': aws_region
            })
        
        # 비정상적인 User-Agent 탐지
        if user_agent and ('bot' in user_agent.lower() or 'crawler' in user_agent.lower()):
            unusual_activities.append({
                'type': 'unusual_user_agent',
                'event_name': event_name,
                'user_agent': user_agent,
                'source_ip': source_ip,
                'time': event_time
            })
    
    # 1. 비정상적인 IP 주소 활동 탐지
    for ip, data in ip_addresses.items():
        # 단일 IP에서 과도한 요청
        if data['count'] > 50:
            issues.append({
                'type': 'excessive_requests_from_ip',
                'risk_level': 'medium',
                'resource': ip,
                'description': f'IP 주소 {ip}에서 24시간 내 {data["count"]}회의 과도한 API 호출',
                'recommendation': 'IP 주소를 확인하고 필요시 차단을 고려하세요.',
                'severity_score': 6.0
            })
        
        # 단일 IP에서 여러 사용자 활동
        if len(data['users']) > 5:
            issues.append({
                'type': 'multiple_users_from_ip',
                'risk_level': 'medium',
                'resource': ip,
                'description': f'IP 주소 {ip}에서 {len(data["users"])}명의 서로 다른 사용자 활동 감지',
                'recommendation': '공유 IP 또는 의심스러운 활동일 수 있으니 확인하세요.',
                'severity_score': 5.5
            })
        
        # 여러 리전에서의 동시 활동
        if len(data['regions']) > 3:
            issues.append({
                'type': 'multi_region_activity',
                'risk_level': 'medium',
                'resource': ip,
                'description': f'IP 주소 {ip}에서 {len(data["regions"])}개 리전에서 동시 활동',
                'recommendation': '지리적으로 분산된 활동이 정상적인지 확인하세요.',
                'severity_score': 5.0
            })
    
    # 2. 사용자별 비정상 활동 탐지
    for username, data in user_activities.items():
        # 단일 사용자의 여러 IP 사용
        if len(data['ips']) > 3:
            issues.append({
                'type': 'user_multiple_ips',
                'risk_level': 'medium',
                'resource': username,
                'description': f'사용자 {username}이 {len(data["ips"])}개의 서로 다른 IP에서 활동',
                'recommendation': '계정 탈취 가능성을 확인하고 필요시 패스워드를 변경하세요.',
                'severity_score': 6.5
            })
        
        # 여러 리전에서의 사용자 활동
        if len(data['regions']) > 2:
            issues.append({
                'type': 'user_multi_region',
                'risk_level': 'low',
                'resource': username,
                'description': f'사용자 {username}이 {len(data["regions"])}개 리전에서 활동',
                'recommendation': '사용자의 정상적인 활동 패턴인지 확인하세요.',
                'severity_score': 3.0
            })
    
    # 3. 실패한 로그인 시도 분석
    if len(failed_logins) > 5:
        # IP별 실패 시도 집계
        failed_by_ip = {}
        for failure in failed_logins:
            ip = failure['ip']
            if ip not in failed_by_ip:
                failed_by_ip[ip] = 0
            failed_by_ip[ip] += 1
        
        for ip, count in failed_by_ip.items():
            if count > 3:
                issues.append({
                    'type': 'brute_force_attempt',
                    'risk_level': 'high',
                    'resource': ip,
                    'description': f'IP 주소 {ip}에서 {count}회의 로그인 실패 시도',
                    'recommendation': 'IP 주소를 차단하고 계정 보안을 강화하세요.',
                    'severity_score': 8.0
                })
    
    # 4. 고위험 이벤트 분석
    if high_risk_events:
        # 짧은 시간 내 여러 고위험 이벤트
        if len(high_risk_events) > 10:
            issues.append({
                'type': 'multiple_high_risk_events',
                'risk_level': 'high',
                'resource': 'Multiple Resources',
                'description': f'24시간 내 {len(high_risk_events)}개의 고위험 이벤트 발생',
                'recommendation': '최근 고위험 활동을 검토하고 승인되지 않은 변경사항이 있는지 확인하세요.',
                'severity_score': 7.5
            })
        
        # 특정 사용자의 과도한 고위험 활동
        user_high_risk = {}
        for event in high_risk_events:
            username = event['username']
            if username not in user_high_risk:
                user_high_risk[username] = 0
            user_high_risk[username] += 1
        
        for username, count in user_high_risk.items():
            if count > 5:
                issues.append({
                    'type': 'user_excessive_high_risk',
                    'risk_level': 'high',
                    'resource': username,
                    'description': f'사용자 {username}이 {count}개의 고위험 작업 수행',
                    'recommendation': '사용자의 활동을 검토하고 필요시 권한을 제한하세요.',
                    'severity_score': 8.5
                })
    
    # 5. 비정상적인 활동 패턴
    for activity in unusual_activities:
        issues.append({
            'type': activity['type'],
            'risk_level': 'low',
            'resource': activity['source_ip'],
            'description': f'비정상적인 User-Agent 탐지: {activity["user_agent"][:50]}...',
            'recommendation': '자동화된 도구 사용 여부를 확인하세요.',
            'severity_score': 2.5
        })
    
    return issues

def summarize_events(events):
    """이벤트 요약 정보 생성"""
    
    if not events:
        return {}
    
    summary = {
        'total_events': len(events),
        'unique_users': len(set(event.get('Username', '') for event in events if event.get('Username'))),
        'unique_ips': len(set(event.get('SourceIPAddress', '') for event in events if event.get('SourceIPAddress'))),
        'unique_regions': len(set(event.get('AwsRegion', '') for event in events if event.get('AwsRegion'))),
        'failed_events': len([event for event in events if event.get('ErrorCode')]),
        'event_types': {},
        'top_users': {},
        'top_ips': {},
        'top_regions': {},
        'hourly_distribution': {}
    }
    
    # 이벤트 타입별 집계
    for event in events:
        event_name = event.get('EventName', 'Unknown')
        if event_name not in summary['event_types']:
            summary['event_types'][event_name] = 0
        summary['event_types'][event_name] += 1
        
        # 사용자별 집계
        username = event.get('Username', '')
        if username:
            if username not in summary['top_users']:
                summary['top_users'][username] = 0
            summary['top_users'][username] += 1
        
        # IP별 집계
        source_ip = event.get('SourceIPAddress', '')
        if source_ip:
            if source_ip not in summary['top_ips']:
                summary['top_ips'][source_ip] = 0
            summary['top_ips'][source_ip] += 1
        
        # 리전별 집계
        region = event.get('AwsRegion', '')
        if region:
            if region not in summary['top_regions']:
                summary['top_regions'][region] = 0
            summary['top_regions'][region] += 1
        
        # 시간별 분포
        event_time = event.get('EventTime')
        if event_time:
            try:
                if isinstance(event_time, str):
                    event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                hour = event_time.hour
                if hour not in summary['hourly_distribution']:
                    summary['hourly_distribution'][hour] = 0
                summary['hourly_distribution'][hour] += 1
            except:
                pass
    
    # 상위 항목들을 정렬하여 제한
    summary['top_users'] = dict(sorted(summary['top_users'].items(), key=lambda x: x[1], reverse=True)[:10])
    summary['top_ips'] = dict(sorted(summary['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
    summary['top_regions'] = dict(sorted(summary['top_regions'].items(), key=lambda x: x[1], reverse=True)[:10])
    summary['event_types'] = dict(sorted(summary['event_types'].items(), key=lambda x: x[1], reverse=True)[:15])
    
    return summary

def perform_cloudtrail_scan(aws_session, deep_scan=False):
    """CloudTrail 로그 스캔 수행"""
    
    try:
        cloudtrail_client = aws_session.client('cloudtrail')
        
        # CloudTrail 데이터 수집
        cloudtrail_data = {
            'trails': [],
            'events': [],
            'trail_status': {}
        }
        
        issues = []
        
        # 1. CloudTrail 트레일 목록 조회
        try:
            trails_response = cloudtrail_client.describe_trails()
            trails = trails_response.get('trailList', [])
            
            if not trails:
                issues.append({
                    'type': 'no_cloudtrail',
                    'risk_level': 'high',
                    'resource': 'CloudTrail',
                    'description': 'CloudTrail이 설정되지 않음',
                    'recommendation': 'CloudTrail을 활성화하여 API 호출을 모니터링하세요.',
                    'severity_score': 8.0
                })
            
            for trail in trails:
                trail_name = trail['Name']
                trail_info = {
                    'name': trail_name,
                    'arn': trail['TrailARN'],
                    's3_bucket': trail.get('S3BucketName'),
                    'include_global_events': trail.get('IncludeGlobalServiceEvents', False),
                    'is_multi_region': trail.get('IsMultiRegionTrail', False),
                    'is_logging': False,
                    'log_file_validation': trail.get('LogFileValidationEnabled', False)
                }
                
                # 트레일 상태 확인
                try:
                    status_response = cloudtrail_client.get_trail_status(Name=trail_name)
                    trail_info['is_logging'] = status_response.get('IsLogging', False)
                    trail_info['latest_delivery_time'] = status_response.get('LatestDeliveryTime')
                    trail_info['latest_delivery_error'] = status_response.get('LatestDeliveryError')
                    
                    # CloudTrail 비활성화 검사
                    if not trail_info['is_logging']:
                        issues.append({
                            'type': 'cloudtrail_not_logging',
                            'risk_level': 'high',
                            'resource': trail_name,
                            'description': f'CloudTrail {trail_name}이 로깅을 중단함',
                            'recommendation': 'CloudTrail 로깅을 즉시 활성화하세요.',
                            'severity_score': 8.5
                        })
                    
                    # 로그 파일 검증 미설정 검사
                    if not trail_info['log_file_validation']:
                        issues.append({
                            'type': 'log_validation_disabled',
                            'risk_level': 'medium',
                            'resource': trail_name,
                            'description': f'CloudTrail {trail_name}의 로그 파일 검증이 비활성화됨',
                            'recommendation': '로그 파일 무결성 검증을 활성화하세요.',
                            'severity_score': 5.0
                        })
                    
                    # 글로벌 서비스 이벤트 미포함 검사
                    if not trail_info['include_global_events']:
                        issues.append({
                            'type': 'global_events_not_included',
                            'risk_level': 'medium',
                            'resource': trail_name,
                            'description': f'CloudTrail {trail_name}이 글로벌 서비스 이벤트를 포함하지 않음',
                            'recommendation': '글로벌 서비스 이벤트 포함을 활성화하세요.',
                            'severity_score': 4.0
                        })
                    
                    # 멀티 리전 트레일 미설정 검사
                    if not trail_info['is_multi_region']:
                        issues.append({
                            'type': 'not_multi_region_trail',
                            'risk_level': 'medium',
                            'resource': trail_name,
                            'description': f'CloudTrail {trail_name}이 멀티 리전 트레일이 아님',
                            'recommendation': '모든 리전의 활동을 모니터링하기 위해 멀티 리전 트레일을 설정하세요.',
                            'severity_score': 4.5
                        })
                    
                except ClientError as e:
                    trail_info['status_error'] = str(e)
                
                cloudtrail_data['trails'].append(trail_info)
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                raise e
        
        # 2. 최근 API 호출 이력 조회 (지난 24시간)
        if deep_scan or len(cloudtrail_data['trails']) > 0:
            try:
                # 최근 24시간 이벤트 조회
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=24)
                
                events_response = cloudtrail_client.lookup_events(
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxItems=100  # 최대 100개 이벤트만 조회
                )
                
                events = events_response.get('Events', [])
                cloudtrail_data['events'] = []
                
                # 의심스러운 활동 패턴 분석
                suspicious_activities = analyze_suspicious_activities(events)
                issues.extend(suspicious_activities)
                
                # 이벤트 요약 정보 생성
                event_summary = summarize_events(events)
                cloudtrail_data['event_summary'] = event_summary
                
                # 주요 이벤트만 저장 (용량 절약)
                for event in events[:20]:  # 최근 20개만 저장
                    event_info = {
                        'event_time': event.get('EventTime'),
                        'event_name': event.get('EventName'),
                        'user_name': event.get('Username'),
                        'source_ip': event.get('SourceIPAddress'),
                        'user_agent': event.get('UserAgent'),
                        'aws_region': event.get('AwsRegion'),
                        'error_code': event.get('ErrorCode'),
                        'error_message': event.get('ErrorMessage')
                    }
                    cloudtrail_data['events'].append(event_info)
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    cloudtrail_data['events_error'] = str(e)
        
        return {
            'data': {
                'trails_count': len(cloudtrail_data['trails']),
                'active_trails': len([t for t in cloudtrail_data['trails'] if t.get('is_logging', False)]),
                'events_analyzed': len(cloudtrail_data.get('events', [])),
                'trails': cloudtrail_data['trails'],
                'events': cloudtrail_data['events'],
                'event_summary': cloudtrail_data.get('event_summary', {})
            },
            'issues': issues
        }
        
    except Exception as e:
        # CloudTrail 스캔 실패 시 기본 정보 반환
        return {
            'data': {
                'trails_count': 0,
                'active_trails': 0,
                'events_analyzed': 0,
                'error': str(e)
            },
            'issues': [{
                'type': 'scan_error',
                'risk_level': 'medium',
                'resource': 'CloudTrail Service',
                'description': f'CloudTrail 스캔 중 오류 발생: {str(e)}',
                'recommendation': 'CloudTrail 읽기 권한을 확인하고 다시 시도하세요.',
                'severity_score': 3.0
            }]
        }

def perform_s3_scan(aws_session, deep_scan=False):
    """S3 보안 스캔 수행"""
    
    try:
        s3_client = aws_session.client('s3')
        
        # S3 데이터 수집
        s3_data = {
            'buckets': [],
            'total_buckets': 0,
            'public_buckets': 0,
            'encrypted_buckets': 0,
            'versioning_enabled': 0,
            'mfa_delete_enabled': 0
        }
        
        issues = []
        
        # 1. S3 버킷 목록 조회
        try:
            buckets_response = s3_client.list_buckets()
            buckets = buckets_response.get('Buckets', [])
            s3_data['total_buckets'] = len(buckets)
            
            if not buckets:
                # 버킷이 없는 경우는 이슈가 아님
                return {
                    'data': s3_data,
                    'issues': []
                }
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                bucket_info = {
                    'name': bucket_name,
                    'creation_date': bucket['CreationDate'],
                    'region': None,
                    'public_access_block': {},
                    'bucket_policy': None,
                    'acl': {},
                    'encryption': {},
                    'versioning': {},
                    'logging': {},
                    'is_public': False,
                    'is_encrypted': False,
                    'versioning_enabled': False,
                    'mfa_delete_enabled': False
                }
                
                try:
                    # 버킷 리전 확인
                    location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_info['region'] = location_response.get('LocationConstraint') or 'us-east-1'
                    
                    # 리전별 클라이언트 생성 (필요한 경우)
                    if bucket_info['region'] != 'us-east-1':
                        try:
                            regional_s3_client = aws_session.client('s3', region_name=bucket_info['region'])
                        except:
                            regional_s3_client = s3_client
                    else:
                        regional_s3_client = s3_client
                    
                    # 2. 각 버킷의 공개 액세스 설정 검사
                    try:
                        public_access_block = regional_s3_client.get_public_access_block(Bucket=bucket_name)
                        bucket_info['public_access_block'] = public_access_block.get('PublicAccessBlockConfiguration', {})
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                            bucket_info['public_access_block'] = {}
                            # 퍼블릭 액세스 블록이 설정되지 않음
                            issues.append({
                                'type': 'no_public_access_block',
                                'risk_level': 'medium',
                                'resource': bucket_name,
                                'description': f'S3 버킷 {bucket_name}에 퍼블릭 액세스 블록이 설정되지 않음',
                                'recommendation': '퍼블릭 액세스 블록을 활성화하여 의도하지 않은 공개를 방지하세요.',
                                'severity_score': 6.0
                            })
                    
                    # 버킷 정책 확인
                    try:
                        bucket_policy = regional_s3_client.get_bucket_policy(Bucket=bucket_name)
                        bucket_info['bucket_policy'] = bucket_policy.get('Policy')
                        
                        # 버킷 정책에서 공개 액세스 확인
                        if bucket_info['bucket_policy'] and '"Principal": "*"' in bucket_info['bucket_policy']:
                            bucket_info['is_public'] = True
                            s3_data['public_buckets'] += 1
                            issues.append({
                                'type': 'public_bucket_policy',
                                'risk_level': 'high',
                                'resource': bucket_name,
                                'description': f'S3 버킷 {bucket_name}의 버킷 정책이 공개 액세스를 허용함',
                                'recommendation': '버킷 정책을 검토하고 불필요한 공개 액세스를 제거하세요.',
                                'severity_score': 9.0
                            })
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                            bucket_info['policy_error'] = str(e)
                    
                    # 버킷 ACL 확인
                    try:
                        bucket_acl = regional_s3_client.get_bucket_acl(Bucket=bucket_name)
                        bucket_info['acl'] = bucket_acl
                        
                        # ACL에서 공개 액세스 확인
                        for grant in bucket_acl.get('Grants', []):
                            grantee = grant.get('Grantee', {})
                            if grantee.get('Type') == 'Group':
                                uri = grantee.get('URI', '')
                                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                    bucket_info['is_public'] = True
                                    if bucket_name not in [issue['resource'] for issue in issues if issue['type'] == 'public_bucket_policy']:
                                        s3_data['public_buckets'] += 1
                                    issues.append({
                                        'type': 'public_bucket_acl',
                                        'risk_level': 'high',
                                        'resource': bucket_name,
                                        'description': f'S3 버킷 {bucket_name}의 ACL이 공개 액세스를 허용함',
                                        'recommendation': 'ACL 설정을 검토하고 공개 액세스를 제거하세요.',
                                        'severity_score': 8.5
                                    })
                                    break
                    except ClientError as e:
                        bucket_info['acl_error'] = str(e)
                    
                    # 3. 버킷 암호화 설정 확인
                    try:
                        encryption_response = regional_s3_client.get_bucket_encryption(Bucket=bucket_name)
                        bucket_info['encryption'] = encryption_response.get('ServerSideEncryptionConfiguration', {})
                        bucket_info['is_encrypted'] = True
                        s3_data['encrypted_buckets'] += 1
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                            bucket_info['is_encrypted'] = False
                            issues.append({
                                'type': 'bucket_not_encrypted',
                                'risk_level': 'medium',
                                'resource': bucket_name,
                                'description': f'S3 버킷 {bucket_name}에 서버 측 암호화가 설정되지 않음',
                                'recommendation': 'S3 버킷에 서버 측 암호화를 활성화하세요.',
                                'severity_score': 5.5
                            })
                    
                    # 4. 버킷 버전 관리 확인
                    try:
                        versioning_response = regional_s3_client.get_bucket_versioning(Bucket=bucket_name)
                        versioning_status = versioning_response.get('Status', 'Disabled')
                        mfa_delete = versioning_response.get('MfaDelete', 'Disabled')
                        
                        bucket_info['versioning'] = {
                            'status': versioning_status,
                            'mfa_delete': mfa_delete
                        }
                        
                        if versioning_status == 'Enabled':
                            bucket_info['versioning_enabled'] = True
                            s3_data['versioning_enabled'] += 1
                            
                            if mfa_delete == 'Enabled':
                                bucket_info['mfa_delete_enabled'] = True
                                s3_data['mfa_delete_enabled'] += 1
                        else:
                            issues.append({
                                'type': 'versioning_disabled',
                                'risk_level': 'low',
                                'resource': bucket_name,
                                'description': f'S3 버킷 {bucket_name}에 버전 관리가 비활성화됨',
                                'recommendation': '데이터 보호를 위해 버전 관리를 활성화하세요.',
                                'severity_score': 3.0
                            })
                    except ClientError as e:
                        bucket_info['versioning_error'] = str(e)
                    
                    # 5. 버킷 로깅 확인 (deep_scan인 경우)
                    if deep_scan:
                        try:
                            logging_response = regional_s3_client.get_bucket_logging(Bucket=bucket_name)
                            bucket_info['logging'] = logging_response.get('LoggingEnabled', {})
                            
                            if not bucket_info['logging']:
                                issues.append({
                                    'type': 'logging_disabled',
                                    'risk_level': 'low',
                                    'resource': bucket_name,
                                    'description': f'S3 버킷 {bucket_name}에 액세스 로깅이 비활성화됨',
                                    'recommendation': '보안 모니터링을 위해 액세스 로깅을 활성화하세요.',
                                    'severity_score': 2.5
                                })
                        except ClientError as e:
                            bucket_info['logging_error'] = str(e)
                        
                        # 6. 버킷 알림 설정 확인
                        try:
                            notification_response = regional_s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
                            bucket_info['notifications'] = notification_response
                        except ClientError as e:
                            bucket_info['notification_error'] = str(e)
                
                except ClientError as e:
                    bucket_info['scan_error'] = str(e)
                    if 'AccessDenied' not in str(e):
                        issues.append({
                            'type': 'bucket_scan_error',
                            'risk_level': 'low',
                            'resource': bucket_name,
                            'description': f'S3 버킷 {bucket_name} 스캔 중 오류: {str(e)}',
                            'recommendation': '버킷 권한을 확인하고 다시 시도하세요.',
                            'severity_score': 1.0
                        })
                
                s3_data['buckets'].append(bucket_info)
            
            # 7. 전체 S3 보안 상태 분석
            if s3_data['total_buckets'] > 0:
                # 공개 버킷 비율이 높은 경우
                public_ratio = s3_data['public_buckets'] / s3_data['total_buckets']
                if public_ratio > 0.2:  # 20% 이상
                    issues.append({
                        'type': 'high_public_bucket_ratio',
                        'risk_level': 'high',
                        'resource': 'S3 Service',
                        'description': f'전체 버킷의 {public_ratio:.1%}가 공개 액세스 허용 ({s3_data["public_buckets"]}/{s3_data["total_buckets"]})',
                        'recommendation': '공개 버킷의 필요성을 재검토하고 불필요한 공개 액세스를 제거하세요.',
                        'severity_score': 8.0
                    })
                
                # 암호화되지 않은 버킷 비율이 높은 경우
                unencrypted_buckets = s3_data['total_buckets'] - s3_data['encrypted_buckets']
                if unencrypted_buckets > 0:
                    unencrypted_ratio = unencrypted_buckets / s3_data['total_buckets']
                    if unencrypted_ratio > 0.5:  # 50% 이상
                        issues.append({
                            'type': 'high_unencrypted_ratio',
                            'risk_level': 'medium',
                            'resource': 'S3 Service',
                            'description': f'전체 버킷의 {unencrypted_ratio:.1%}가 암호화되지 않음 ({unencrypted_buckets}/{s3_data["total_buckets"]})',
                            'recommendation': '모든 S3 버킷에 서버 측 암호화를 적용하세요.',
                            'severity_score': 6.5
                        })
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                raise e
        
        return {
            'data': s3_data,
            'issues': issues
        }
        
    except Exception as e:
        # S3 스캔 실패 시 기본 정보 반환
        return {
            'data': {
                'total_buckets': 0,
                'public_buckets': 0,
                'encrypted_buckets': 0,
                'error': str(e)
            },
            'issues': [{
                'type': 'scan_error',
                'risk_level': 'medium',
                'resource': 'S3 Service',
                'description': f'S3 스캔 중 오류 발생: {str(e)}',
                'recommendation': 'S3 읽기 권한을 확인하고 다시 시도하세요.',
                'severity_score': 3.0
            }]
        }

def perform_guardduty_scan(aws_session, deep_scan=False):
    """GuardDuty 스캔 수행"""
    
    try:
        guardduty_client = aws_session.client('guardduty')
        
        # GuardDuty 데이터 수집
        guardduty_data = {
            'detectors': [],
            'findings': [],
            'total_detectors': 0,
            'active_detectors': 0,
            'total_findings': 0,
            'high_severity_findings': 0,
            'medium_severity_findings': 0,
            'low_severity_findings': 0
        }
        
        issues = []
        
        # 1. GuardDuty 디텍터 목록 조회
        try:
            detectors_response = guardduty_client.list_detectors()
            detector_ids = detectors_response.get('DetectorIds', [])
            guardduty_data['total_detectors'] = len(detector_ids)
            
            if not detector_ids:
                # GuardDuty가 활성화되지 않음
                issues.append({
                    'type': 'guardduty_not_enabled',
                    'risk_level': 'high',
                    'resource': 'GuardDuty Service',
                    'description': 'GuardDuty가 활성화되지 않음',
                    'recommendation': 'GuardDuty를 활성화하여 위협 탐지 기능을 사용하세요.',
                    'severity_score': 8.0
                })
                
                return {
                    'data': guardduty_data,
                    'issues': issues
                }
            
            # 각 디텍터 정보 수집
            for detector_id in detector_ids:
                try:
                    detector_response = guardduty_client.get_detector(DetectorId=detector_id)
                    
                    detector_info = {
                        'id': detector_id,
                        'status': detector_response.get('Status'),
                        'service_role': detector_response.get('ServiceRole'),
                        'finding_publishing_frequency': detector_response.get('FindingPublishingFrequency'),
                        'created_at': detector_response.get('CreatedAt'),
                        'updated_at': detector_response.get('UpdatedAt'),
                        'data_sources': detector_response.get('DataSources', {}),
                        'tags': detector_response.get('Tags', {})
                    }
                    
                    if detector_info['status'] == 'ENABLED':
                        guardduty_data['active_detectors'] += 1
                    else:
                        issues.append({
                            'type': 'guardduty_detector_disabled',
                            'risk_level': 'high',
                            'resource': f'Detector {detector_id}',
                            'description': f'GuardDuty 디텍터 {detector_id}가 비활성화됨',
                            'recommendation': 'GuardDuty 디텍터를 활성화하세요.',
                            'severity_score': 7.5
                        })
                    
                    # 데이터 소스 확인
                    data_sources = detector_info.get('data_sources', {})
                    
                    # S3 로그 데이터 소스 확인
                    s3_logs = data_sources.get('S3Logs', {})
                    if s3_logs.get('Status') != 'ENABLED':
                        issues.append({
                            'type': 'guardduty_s3_logs_disabled',
                            'risk_level': 'medium',
                            'resource': f'Detector {detector_id}',
                            'description': f'GuardDuty S3 로그 모니터링이 비활성화됨',
                            'recommendation': 'S3 로그 모니터링을 활성화하여 S3 관련 위협을 탐지하세요.',
                            'severity_score': 5.0
                        })
                    
                    # Kubernetes 감사 로그 확인
                    kubernetes_logs = data_sources.get('Kubernetes', {}).get('AuditLogs', {})
                    if kubernetes_logs.get('Status') != 'ENABLED' and deep_scan:
                        issues.append({
                            'type': 'guardduty_kubernetes_disabled',
                            'risk_level': 'low',
                            'resource': f'Detector {detector_id}',
                            'description': f'GuardDuty Kubernetes 감사 로그 모니터링이 비활성화됨',
                            'recommendation': 'Kubernetes 클러스터가 있다면 감사 로그 모니터링을 활성화하세요.',
                            'severity_score': 3.0
                        })
                    
                    # Malware Protection 확인
                    malware_protection = data_sources.get('MalwareProtection', {})
                    if malware_protection.get('Status') != 'ENABLED':
                        issues.append({
                            'type': 'guardduty_malware_protection_disabled',
                            'risk_level': 'medium',
                            'resource': f'Detector {detector_id}',
                            'description': f'GuardDuty 악성코드 보호 기능이 비활성화됨',
                            'recommendation': '악성코드 보호 기능을 활성화하여 EC2 및 컨테이너 워크로드를 보호하세요.',
                            'severity_score': 6.0
                        })
                    
                    guardduty_data['detectors'].append(detector_info)
                    
                    # 2. GuardDuty 발견 사항(Findings) 조회
                    if detector_info['status'] == 'ENABLED':
                        try:
                            # 최근 30일간의 발견 사항 조회
                            findings_response = guardduty_client.list_findings(
                                DetectorId=detector_id,
                                FindingCriteria={
                                    'Criterion': {
                                        'updatedAt': {
                                            'Gte': int((datetime.now() - timedelta(days=30)).timestamp() * 1000)
                                        }
                                    }
                                },
                                MaxResults=50  # 최대 50개 발견 사항
                            )
                            
                            finding_ids = findings_response.get('FindingIds', [])
                            guardduty_data['total_findings'] += len(finding_ids)
                            
                            if finding_ids:
                                # 발견 사항 상세 정보 조회
                                findings_details = guardduty_client.get_findings(
                                    DetectorId=detector_id,
                                    FindingIds=finding_ids
                                )
                                
                                for finding in findings_details.get('Findings', []):
                                    finding_info = {
                                        'id': finding.get('Id'),
                                        'type': finding.get('Type'),
                                        'title': finding.get('Title'),
                                        'description': finding.get('Description'),
                                        'severity': finding.get('Severity'),
                                        'confidence': finding.get('Confidence'),
                                        'created_at': finding.get('CreatedAt'),
                                        'updated_at': finding.get('UpdatedAt'),
                                        'region': finding.get('Region'),
                                        'resource': finding.get('Resource', {}),
                                        'service': finding.get('Service', {}),
                                        'schema_version': finding.get('SchemaVersion'),
                                        'partition': finding.get('Partition')
                                    }
                                    
                                    # 심각도별 분류
                                    severity = finding_info['severity']
                                    if severity >= 7.0:
                                        guardduty_data['high_severity_findings'] += 1
                                        risk_level = 'high'
                                        severity_score = 9.0
                                    elif severity >= 4.0:
                                        guardduty_data['medium_severity_findings'] += 1
                                        risk_level = 'medium'
                                        severity_score = 6.0
                                    else:
                                        guardduty_data['low_severity_findings'] += 1
                                        risk_level = 'low'
                                        severity_score = 3.0
                                    
                                    # 발견 사항을 이슈로 변환
                                    resource_info = finding_info.get('resource', {})
                                    resource_type = resource_info.get('ResourceType', 'Unknown')
                                    
                                    if resource_type == 'Instance':
                                        resource_name = resource_info.get('InstanceDetails', {}).get('InstanceId', 'Unknown Instance')
                                    elif resource_type == 'S3Bucket':
                                        resource_name = resource_info.get('S3BucketDetails', [{}])[0].get('Name', 'Unknown Bucket')
                                    else:
                                        resource_name = f"{resource_type} Resource"
                                    
                                    issues.append({
                                        'type': f'guardduty_{finding_info["type"].lower().replace(".", "_")}',
                                        'risk_level': risk_level,
                                        'resource': resource_name,
                                        'description': f'GuardDuty 발견: {finding_info["title"]} - {finding_info["description"][:100]}...',
                                        'recommendation': get_guardduty_recommendation(finding_info['type']),
                                        'severity_score': severity_score,
                                        'finding_details': {
                                            'id': finding_info['id'],
                                            'type': finding_info['type'],
                                            'severity': finding_info['severity'],
                                            'confidence': finding_info['confidence'],
                                            'created_at': finding_info['created_at'],
                                            'region': finding_info['region']
                                        }
                                    })
                                    
                                    guardduty_data['findings'].append(finding_info)
                        
                        except ClientError as e:
                            if e.response['Error']['Code'] != 'AccessDenied':
                                detector_info['findings_error'] = str(e)
                
                except ClientError as e:
                    if e.response['Error']['Code'] != 'AccessDenied':
                        issues.append({
                            'type': 'guardduty_detector_error',
                            'risk_level': 'low',
                            'resource': f'Detector {detector_id}',
                            'description': f'GuardDuty 디텍터 {detector_id} 조회 중 오류: {str(e)}',
                            'recommendation': 'GuardDuty 권한을 확인하고 다시 시도하세요.',
                            'severity_score': 2.0
                        })
        
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                raise e
        
        # 3. GuardDuty 전체 상태 분석
        if guardduty_data['total_detectors'] > 0:
            # 높은 심각도 발견 사항이 많은 경우
            if guardduty_data['high_severity_findings'] > 5:
                issues.append({
                    'type': 'multiple_high_severity_findings',
                    'risk_level': 'high',
                    'resource': 'GuardDuty Service',
                    'description': f'{guardduty_data["high_severity_findings"]}개의 높은 심각도 GuardDuty 발견 사항',
                    'recommendation': '높은 심각도 발견 사항을 즉시 검토하고 대응하세요.',
                    'severity_score': 9.5
                })
            
            # 전체 발견 사항이 많은 경우
            if guardduty_data['total_findings'] > 20:
                issues.append({
                    'type': 'excessive_guardduty_findings',
                    'risk_level': 'medium',
                    'resource': 'GuardDuty Service',
                    'description': f'총 {guardduty_data["total_findings"]}개의 GuardDuty 발견 사항 (최근 30일)',
                    'recommendation': '발견 사항을 정기적으로 검토하고 보안 태세를 개선하세요.',
                    'severity_score': 5.5
                })
        
        return {
            'data': guardduty_data,
            'issues': issues
        }
        
    except Exception as e:
        # GuardDuty 스캔 실패 시 기본 정보 반환
        return {
            'data': {
                'total_detectors': 0,
                'active_detectors': 0,
                'total_findings': 0,
                'error': str(e)
            },
            'issues': [{
                'type': 'scan_error',
                'risk_level': 'medium',
                'resource': 'GuardDuty Service',
                'description': f'GuardDuty 스캔 중 오류 발생: {str(e)}',
                'recommendation': 'GuardDuty 읽기 권한을 확인하고 다시 시도하세요.',
                'severity_score': 3.0
            }]
        }

def get_guardduty_recommendation(finding_type):
    """GuardDuty 발견 사항 유형별 권장 조치 반환"""
    
    recommendations = {
        'Backdoor': '백도어 활동이 탐지되었습니다. 해당 리소스를 격리하고 보안 분석을 수행하세요.',
        'Behavior': '비정상적인 행동이 탐지되었습니다. 활동 로그를 검토하고 필요시 대응하세요.',
        'Cryptocurrency': '암호화폐 채굴 활동이 탐지되었습니다. 해당 인스턴스를 즉시 격리하세요.',
        'Malware': '악성코드가 탐지되었습니다. 안티바이러스 스캔을 실행하고 시스템을 정리하세요.',
        'Pentest': '침투 테스트 도구 사용이 탐지되었습니다. 승인된 활동인지 확인하세요.',
        'Policy': '정책 위반이 탐지되었습니다. 보안 정책을 검토하고 준수하세요.',
        'Recon': '정찰 활동이 탐지되었습니다. 네트워크 접근을 제한하고 모니터링을 강화하세요.',
        'ResourceConsumption': '리소스 남용이 탐지되었습니다. 사용량을 모니터링하고 제한하세요.',
        'Stealth': '은밀한 활동이 탐지되었습니다. 시스템 로그를 상세히 분석하세요.',
        'Trojan': '트로이목마가 탐지되었습니다. 시스템을 격리하고 완전한 보안 스캔을 수행하세요.',
        'UnauthorizedAccess': '무단 접근이 탐지되었습니다. 접근 권한을 검토하고 계정을 보호하세요.'
    }
    
    # 발견 사항 유형에서 주요 키워드 추출
    for key, recommendation in recommendations.items():
        if key.lower() in finding_type.lower():
            return recommendation
    
    return 'GuardDuty 발견 사항을 검토하고 적절한 보안 조치를 취하세요.'

def perform_waf_scan(aws_session, deep_scan=False):
    """WAF 스캔 수행"""
    
    try:
        wafv2_client = aws_session.client('wafv2')
        
        # WAF 데이터 수집
        waf_data = {
            'regional_web_acls': [],
            'cloudfront_web_acls': [],
            'total_web_acls': 0,
            'total_rules': 0,
            'managed_rules': 0,
            'custom_rules': 0,
            'rate_limiting_rules': 0,
            'geo_blocking_rules': 0
        }
        
        issues = []
        
        # 1. Regional WAF WebACLs 조회 (ALB, API Gateway 등)
        try:
            regional_web_acls = wafv2_client.list_web_acls(Scope='REGIONAL')
            regional_acls = regional_web_acls.get('WebACLs', [])
            
            for web_acl in regional_acls:
                acl_info = analyze_web_acl(wafv2_client, web_acl, 'REGIONAL', deep_scan)
                waf_data['regional_web_acls'].append(acl_info)
                waf_data['total_rules'] += acl_info.get('rules_count', 0)
                waf_data['managed_rules'] += acl_info.get('managed_rules_count', 0)
                waf_data['custom_rules'] += acl_info.get('custom_rules_count', 0)
                waf_data['rate_limiting_rules'] += acl_info.get('rate_limiting_count', 0)
                waf_data['geo_blocking_rules'] += acl_info.get('geo_blocking_count', 0)
                
                # WebACL별 이슈 수집
                issues.extend(acl_info.get('issues', []))
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                issues.append({
                    'type': 'waf_regional_scan_error',
                    'risk_level': 'low',
                    'resource': 'WAF Regional',
                    'description': f'Regional WAF 스캔 중 오류: {str(e)}',
                    'recommendation': 'WAF 읽기 권한을 확인하고 다시 시도하세요.',
                    'severity_score': 2.0
                })
        
        # 2. CloudFront WAF WebACLs 조회
        try:
            cloudfront_web_acls = wafv2_client.list_web_acls(Scope='CLOUDFRONT')
            cloudfront_acls = cloudfront_web_acls.get('WebACLs', [])
            
            for web_acl in cloudfront_acls:
                acl_info = analyze_web_acl(wafv2_client, web_acl, 'CLOUDFRONT', deep_scan)
                waf_data['cloudfront_web_acls'].append(acl_info)
                waf_data['total_rules'] += acl_info.get('rules_count', 0)
                waf_data['managed_rules'] += acl_info.get('managed_rules_count', 0)
                waf_data['custom_rules'] += acl_info.get('custom_rules_count', 0)
                waf_data['rate_limiting_rules'] += acl_info.get('rate_limiting_count', 0)
                waf_data['geo_blocking_rules'] += acl_info.get('geo_blocking_count', 0)
                
                # WebACL별 이슈 수집
                issues.extend(acl_info.get('issues', []))
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                issues.append({
                    'type': 'waf_cloudfront_scan_error',
                    'risk_level': 'low',
                    'resource': 'WAF CloudFront',
                    'description': f'CloudFront WAF 스캔 중 오류: {str(e)}',
                    'recommendation': 'WAF 읽기 권한을 확인하고 다시 시도하세요.',
                    'severity_score': 2.0
                })
        
        # 전체 WebACL 수 계산
        waf_data['total_web_acls'] = len(waf_data['regional_web_acls']) + len(waf_data['cloudfront_web_acls'])
        
        # 3. WAF 전체 상태 분석
        if waf_data['total_web_acls'] == 0:
            issues.append({
                'type': 'no_waf_configured',
                'risk_level': 'medium',
                'resource': 'WAF Service',
                'description': 'WAF가 설정되지 않음',
                'recommendation': '웹 애플리케이션 보호를 위해 WAF를 설정하세요.',
                'severity_score': 5.0
            })
        else:
            # WAF는 있지만 규칙이 부족한 경우
            if waf_data['total_rules'] < 5:
                issues.append({
                    'type': 'insufficient_waf_rules',
                    'risk_level': 'medium',
                    'resource': 'WAF Service',
                    'description': f'WAF 규칙이 부족함 (총 {waf_data["total_rules"]}개)',
                    'recommendation': '더 많은 보안 규칙을 추가하여 웹 애플리케이션을 보호하세요.',
                    'severity_score': 4.5
                })
            
            # 관리형 규칙이 없는 경우
            if waf_data['managed_rules'] == 0:
                issues.append({
                    'type': 'no_managed_rules',
                    'risk_level': 'medium',
                    'resource': 'WAF Service',
                    'description': 'AWS 관리형 규칙이 설정되지 않음',
                    'recommendation': 'AWS 관리형 규칙을 추가하여 일반적인 웹 공격을 차단하세요.',
                    'severity_score': 5.5
                })
            
            # Rate limiting이 없는 경우
            if waf_data['rate_limiting_rules'] == 0:
                issues.append({
                    'type': 'no_rate_limiting',
                    'risk_level': 'low',
                    'resource': 'WAF Service',
                    'description': 'Rate limiting 규칙이 설정되지 않음',
                    'recommendation': 'DDoS 공격 방지를 위해 Rate limiting 규칙을 추가하세요.',
                    'severity_score': 3.5
                })
        
        return {
            'data': waf_data,
            'issues': issues
        }
        
    except Exception as e:
        # WAF 스캔 실패 시 기본 정보 반환
        return {
            'data': {
                'total_web_acls': 0,
                'total_rules': 0,
                'error': str(e)
            },
            'issues': [{
                'type': 'scan_error',
                'risk_level': 'medium',
                'resource': 'WAF Service',
                'description': f'WAF 스캔 중 오류 발생: {str(e)}',
                'recommendation': 'WAF 읽기 권한을 확인하고 다시 시도하세요.',
                'severity_score': 3.0
            }]
        }

def analyze_web_acl(wafv2_client, web_acl_summary, scope, deep_scan=False):
    """개별 WebACL 분석"""
    
    acl_info = {
        'name': web_acl_summary.get('Name'),
        'id': web_acl_summary.get('Id'),
        'arn': web_acl_summary.get('ARN'),
        'scope': scope,
        'description': web_acl_summary.get('Description', ''),
        'rules': [],
        'rules_count': 0,
        'managed_rules_count': 0,
        'custom_rules_count': 0,
        'rate_limiting_count': 0,
        'geo_blocking_count': 0,
        'default_action': None,
        'associated_resources': [],
        'issues': []
    }
    
    try:
        # WebACL 상세 정보 조회
        web_acl_detail = wafv2_client.get_web_acl(
            Name=acl_info['name'],
            Id=acl_info['id'],
            Scope=scope
        )
        
        web_acl_data = web_acl_detail.get('WebACL', {})
        acl_info['default_action'] = web_acl_data.get('DefaultAction', {})
        
        # 규칙 분석
        rules = web_acl_data.get('Rules', [])
        acl_info['rules_count'] = len(rules)
        
        for rule in rules:
            rule_info = {
                'name': rule.get('Name'),
                'priority': rule.get('Priority'),
                'action': rule.get('Action', {}),
                'statement': rule.get('Statement', {}),
                'visibility_config': rule.get('VisibilityConfig', {})
            }
            
            # 규칙 유형 분석
            statement = rule.get('Statement', {})
            
            # 관리형 규칙 그룹 확인
            if 'ManagedRuleGroupStatement' in statement:
                acl_info['managed_rules_count'] += 1
                managed_rule = statement['ManagedRuleGroupStatement']
                rule_info['type'] = 'managed'
                rule_info['vendor_name'] = managed_rule.get('VendorName')
                rule_info['rule_group_name'] = managed_rule.get('Name')
                
                # 일반적인 보안 규칙 그룹 확인
                rule_group_name = managed_rule.get('Name', '').lower()
                if 'core' not in rule_group_name and 'owasp' not in rule_group_name:
                    acl_info['issues'].append({
                        'type': 'missing_core_rules',
                        'risk_level': 'medium',
                        'resource': acl_info['name'],
                        'description': f'WebACL {acl_info["name"]}에 핵심 보안 규칙이 부족할 수 있음',
                        'recommendation': 'AWS Core Rule Set 또는 OWASP Top 10 규칙을 추가하세요.',
                        'severity_score': 4.0
                    })
            
            # Rate limiting 규칙 확인
            elif 'RateBasedStatement' in statement:
                acl_info['rate_limiting_count'] += 1
                rule_info['type'] = 'rate_limiting'
                rate_limit = statement['RateBasedStatement'].get('Limit', 0)
                rule_info['rate_limit'] = rate_limit
                
                # Rate limit이 너무 높은 경우
                if rate_limit > 10000:
                    acl_info['issues'].append({
                        'type': 'high_rate_limit',
                        'risk_level': 'low',
                        'resource': acl_info['name'],
                        'description': f'Rate limit이 너무 높음 ({rate_limit})',
                        'recommendation': 'Rate limit을 적절한 수준으로 조정하세요.',
                        'severity_score': 2.5
                    })
            
            # 지리적 차단 규칙 확인
            elif 'GeoMatchStatement' in statement:
                acl_info['geo_blocking_count'] += 1
                rule_info['type'] = 'geo_blocking'
                rule_info['country_codes'] = statement['GeoMatchStatement'].get('CountryCodes', [])
            
            # IP 세트 규칙 확인
            elif 'IPSetReferenceStatement' in statement:
                rule_info['type'] = 'ip_set'
                rule_info['ip_set_arn'] = statement['IPSetReferenceStatement'].get('ARN')
            
            # 사용자 정의 규칙
            else:
                acl_info['custom_rules_count'] += 1
                rule_info['type'] = 'custom'
            
            acl_info['rules'].append(rule_info)
        
        # 기본 액션 분석
        default_action = acl_info.get('default_action', {})
        if 'Allow' in default_action:
            # 기본 허용이면서 차단 규칙이 부족한 경우
            if acl_info['rules_count'] < 3:
                acl_info['issues'].append({
                    'type': 'permissive_default_action',
                    'risk_level': 'medium',
                    'resource': acl_info['name'],
                    'description': f'WebACL {acl_info["name"]}이 기본 허용이면서 차단 규칙이 부족함',
                    'recommendation': '더 많은 보안 규칙을 추가하거나 기본 액션을 차단으로 변경하세요.',
                    'severity_score': 5.0
                })
        
        # 연결된 리소스 확인 (deep_scan인 경우)
        if deep_scan:
            try:
                associated_resources = wafv2_client.list_resources_for_web_acl(
                    WebACLArn=acl_info['arn'],
                    ResourceType='APPLICATION_LOAD_BALANCER'
                )
                acl_info['associated_resources'].extend(associated_resources.get('ResourceArns', []))
                
                # API Gateway 리소스도 확인
                api_resources = wafv2_client.list_resources_for_web_acl(
                    WebACLArn=acl_info['arn'],
                    ResourceType='API_GATEWAY'
                )
                acl_info['associated_resources'].extend(api_resources.get('ResourceArns', []))
                
                # CloudFront인 경우
                if scope == 'CLOUDFRONT':
                    cf_resources = wafv2_client.list_resources_for_web_acl(
                        WebACLArn=acl_info['arn'],
                        ResourceType='CLOUDFRONT'
                    )
                    acl_info['associated_resources'].extend(cf_resources.get('ResourceArns', []))
                
                # 연결된 리소스가 없는 경우
                if not acl_info['associated_resources']:
                    acl_info['issues'].append({
                        'type': 'unused_web_acl',
                        'risk_level': 'low',
                        'resource': acl_info['name'],
                        'description': f'WebACL {acl_info["name"]}이 어떤 리소스에도 연결되지 않음',
                        'recommendation': '사용하지 않는 WebACL을 삭제하거나 리소스에 연결하세요.',
                        'severity_score': 1.5
                    })
                
            except ClientError as e:
                acl_info['resource_error'] = str(e)
    
    except ClientError as e:
        acl_info['analysis_error'] = str(e)
        acl_info['issues'].append({
            'type': 'web_acl_analysis_error',
            'risk_level': 'low',
            'resource': acl_info['name'],
            'description': f'WebACL {acl_info["name"]} 분석 중 오류: {str(e)}',
            'recommendation': 'WAF 권한을 확인하고 다시 시도하세요.',
            'severity_score': 1.0
        })
    
    return acl_info

def show_dashboard():
    """메인 대시보드 표시"""
    
    # 스캔 결과 데이터 가져오기
    scan_results = st.session_state.get('scan_results', {})
    summary = scan_results.get('summary', {})
    account_info = st.session_state.get('account_info', {})
    
    # 대시보드 헤더
    st.markdown("# 🔒 AWS 보안 대시보드")
    
    # 스캔 완료 시간 표시
    if 'scan_end_time' in st.session_state:
        scan_time = st.session_state.scan_end_time
        st.caption(f"마지막 스캔: {scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    st.markdown("---")
    
    # 1. 전체 보안 상태 요약
    show_security_overview(summary, account_info)
    
    st.markdown("---")
    
    # 2. 보안 상태 시각화
    show_enhanced_dashboard_with_charts()
    
    st.markdown("---")
    
    # 3. 서비스별 상세 대시보드
    show_service_dashboard(scan_results)
    
    st.markdown("---")
    
    # 3. 우선순위 이슈 및 권장사항
    show_priority_issues_and_recommendations(scan_results)
    
    st.markdown("---")
    
    # 4. 대시보드 액션
    show_dashboard_actions()

def show_security_overview(summary, account_info):
    """전체 보안 상태 요약 표시"""
    
    st.markdown("## 📊 전체 보안 상태")
    
    # 보안 점수 및 주요 지표
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        security_score = summary.get('security_score', 0)
        score_color = get_score_color(security_score)
        st.metric(
            "보안 점수", 
            f"{security_score}/100",
            help="전체 보안 상태를 0-100점으로 평가"
        )
        st.markdown(f"<div style='color: {score_color}; font-weight: bold; text-align: center;'>{get_score_grade(security_score)}</div>", 
                   unsafe_allow_html=True)
    
    with col2:
        total_issues = summary.get('total_issues', 0)
        st.metric(
            "총 이슈", 
            total_issues,
            help="발견된 전체 보안 이슈 수"
        )
    
    with col3:
        high_risk = summary.get('high_risk', 0)
        st.metric(
            "높은 위험", 
            high_risk,
            delta=f"-{high_risk}" if high_risk > 0 else None,
            delta_color="inverse",
            help="즉시 해결이 필요한 높은 위험도 이슈"
        )
    
    with col4:
        medium_risk = summary.get('medium_risk', 0)
        st.metric(
            "중간 위험", 
            medium_risk,
            help="단기간 내 해결 권장 이슈"
        )
    
    with col5:
        services_scanned = summary.get('services_scanned', 0)
        services_failed = summary.get('services_failed', 0)
        st.metric(
            "스캔 완료", 
            f"{services_scanned}/5",
            delta=f"-{services_failed} 실패" if services_failed > 0 else "모두 성공",
            delta_color="inverse" if services_failed > 0 else "normal",
            help="스캔 완료된 서비스 수"
        )
    
    # 계정 정보 표시
    if account_info:
        st.markdown("### 📋 계정 정보")
        info_col1, info_col2, info_col3 = st.columns(3)
        
        with info_col1:
            st.info(f"**계정 ID**: {account_info.get('account_id', 'N/A')}")
        with info_col2:
            st.info(f"**리전**: {account_info.get('region', 'N/A')}")
        with info_col3:
            connection_type = "인스턴스 프로파일" if account_info.get('use_instance_profile') else "수동 입력"
            st.info(f"**연결 방식**: {connection_type}")

def show_service_dashboard(scan_results):
    """서비스별 상세 대시보드"""
    
    st.markdown("## 🛡️ 서비스별 보안 상태")
    
    # 서비스별 탭 생성
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔐 IAM 계정 관리", 
        "📋 CloudTrail 모니터링", 
        "🗄️ S3 데이터 보안", 
        "🛡️ GuardDuty 위협 탐지", 
        "🌐 WAF 네트워크 보안"
    ])
    
    with tab1:
        show_iam_dashboard(scan_results.get('iam', {}))
    
    with tab2:
        show_cloudtrail_dashboard(scan_results.get('cloudtrail', {}))
    
    with tab3:
        show_s3_dashboard(scan_results.get('s3', {}))
    
    with tab4:
        show_guardduty_dashboard(scan_results.get('guardduty', {}))
    
    with tab5:
        show_waf_dashboard(scan_results.get('waf', {}))

def show_iam_dashboard(iam_data):
    """IAM 대시보드"""
    
    if iam_data.get('status') != 'completed':
        st.error("IAM 스캔이 완료되지 않았습니다.")
        return
    
    data = iam_data.get('data', {})
    issues = iam_data.get('issues', [])
    
    # IAM 리소스 현황
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("IAM 사용자", data.get('users_count', 0))
    with col2:
        st.metric("IAM 역할", data.get('roles_count', 0))
    with col3:
        st.metric("IAM 그룹", data.get('groups_count', 0))
    with col4:
        mfa_enabled = len([u for u in data.get('users', []) if u.get('mfa_enabled')])
        total_users = data.get('users_count', 0)
        mfa_rate = f"{mfa_enabled}/{total_users}" if total_users > 0 else "0/0"
        st.metric("MFA 활성화", mfa_rate)
    
    # IAM 이슈 요약
    if issues:
        st.markdown("### 🚨 IAM 보안 이슈")
        
        high_issues = [i for i in issues if i.get('risk_level') == 'high']
        medium_issues = [i for i in issues if i.get('risk_level') == 'medium']
        
        if high_issues:
            st.error(f"**높은 위험 이슈 {len(high_issues)}개**")
            for issue in high_issues[:3]:  # 상위 3개만 표시
                st.markdown(f"- {issue.get('description', '')}")
        
        if medium_issues:
            st.warning(f"**중간 위험 이슈 {len(medium_issues)}개**")
            for issue in medium_issues[:3]:
                st.markdown(f"- {issue.get('description', '')}")
    else:
        st.success("✅ IAM 관련 보안 이슈가 발견되지 않았습니다.")

def show_cloudtrail_dashboard(cloudtrail_data):
    """CloudTrail 대시보드"""
    
    if cloudtrail_data.get('status') != 'completed':
        st.error("CloudTrail 스캔이 완료되지 않았습니다.")
        return
    
    data = cloudtrail_data.get('data', {})
    issues = cloudtrail_data.get('issues', [])
    
    # CloudTrail 현황
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("CloudTrail 수", data.get('trails_count', 0))
    with col2:
        st.metric("활성 트레일", data.get('active_trails', 0))
    with col3:
        st.metric("분석된 이벤트", data.get('events_analyzed', 0))
    
    # 이벤트 요약 (있는 경우)
    event_summary = data.get('event_summary', {})
    if event_summary:
        st.markdown("### 📈 최근 24시간 활동")
        
        summary_col1, summary_col2, summary_col3 = st.columns(3)
        with summary_col1:
            st.metric("고유 사용자", event_summary.get('unique_users', 0))
        with summary_col2:
            st.metric("고유 IP", event_summary.get('unique_ips', 0))
        with summary_col3:
            st.metric("실패한 이벤트", event_summary.get('failed_events', 0))
    
    # CloudTrail 이슈
    if issues:
        st.markdown("### 🚨 CloudTrail 보안 이슈")
        show_issues_summary(issues)
    else:
        st.success("✅ CloudTrail 관련 보안 이슈가 발견되지 않았습니다.")

def show_s3_dashboard(s3_data):
    """S3 대시보드"""
    
    if s3_data.get('status') != 'completed':
        st.error("S3 스캔이 완료되지 않았습니다.")
        return
    
    data = s3_data.get('data', {})
    issues = s3_data.get('issues', [])
    
    # S3 현황
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("총 버킷", data.get('total_buckets', 0))
    with col2:
        public_buckets = data.get('public_buckets', 0)
        st.metric("공개 버킷", public_buckets, 
                 delta=f"-{public_buckets}" if public_buckets > 0 else None,
                 delta_color="inverse")
    with col3:
        encrypted_buckets = data.get('encrypted_buckets', 0)
        st.metric("암호화된 버킷", encrypted_buckets)
    with col4:
        versioning_enabled = data.get('versioning_enabled', 0)
        st.metric("버전 관리 활성", versioning_enabled)
    
    # S3 이슈
    if issues:
        st.markdown("### 🚨 S3 보안 이슈")
        show_issues_summary(issues)
    else:
        st.success("✅ S3 관련 보안 이슈가 발견되지 않았습니다.")

def show_guardduty_dashboard(guardduty_data):
    """GuardDuty 대시보드"""
    
    if guardduty_data.get('status') != 'completed':
        st.error("GuardDuty 스캔이 완료되지 않았습니다.")
        return
    
    data = guardduty_data.get('data', {})
    issues = guardduty_data.get('issues', [])
    
    # GuardDuty 현황
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("디텍터", data.get('total_detectors', 0))
    with col2:
        st.metric("활성 디텍터", data.get('active_detectors', 0))
    with col3:
        st.metric("총 발견사항", data.get('total_findings', 0))
    with col4:
        high_findings = data.get('high_severity_findings', 0)
        st.metric("높은 심각도", high_findings,
                 delta=f"-{high_findings}" if high_findings > 0 else None,
                 delta_color="inverse")
    
    # GuardDuty 이슈
    if issues:
        st.markdown("### 🚨 GuardDuty 보안 이슈")
        show_issues_summary(issues)
    else:
        st.success("✅ GuardDuty 관련 보안 이슈가 발견되지 않았습니다.")

def show_waf_dashboard(waf_data):
    """WAF 대시보드"""
    
    if waf_data.get('status') != 'completed':
        st.error("WAF 스캔이 완료되지 않았습니다.")
        return
    
    data = waf_data.get('data', {})
    issues = waf_data.get('issues', [])
    
    # WAF 현황
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Web ACL", data.get('total_web_acls', 0))
    with col2:
        st.metric("총 규칙", data.get('total_rules', 0))
    with col3:
        st.metric("관리형 규칙", data.get('managed_rules', 0))
    with col4:
        st.metric("Rate Limiting", data.get('rate_limiting_rules', 0))
    
    # WAF 이슈
    if issues:
        st.markdown("### 🚨 WAF 보안 이슈")
        show_issues_summary(issues)
    else:
        st.success("✅ WAF 관련 보안 이슈가 발견되지 않았습니다.")

def show_issues_summary(issues):
    """이슈 요약 표시"""
    
    high_issues = [i for i in issues if i.get('risk_level') == 'high']
    medium_issues = [i for i in issues if i.get('risk_level') == 'medium']
    low_issues = [i for i in issues if i.get('risk_level') == 'low']
    
    if high_issues:
        st.error(f"**높은 위험 이슈 {len(high_issues)}개**")
        for issue in high_issues[:3]:
            st.markdown(f"- {issue.get('description', '')}")
    
    if medium_issues:
        st.warning(f"**중간 위험 이슈 {len(medium_issues)}개**")
        for issue in medium_issues[:2]:
            st.markdown(f"- {issue.get('description', '')}")
    
    if low_issues:
        st.info(f"**낮은 위험 이슈 {len(low_issues)}개**")

def show_priority_issues_and_recommendations(scan_results):
    """우선순위 이슈 및 권장사항 표시"""
    
    st.markdown("## 🎯 우선순위 이슈 및 권장사항")
    
    summary = scan_results.get('summary', {})
    priority_issues = summary.get('priority_issues', [])
    
    if not priority_issues:
        st.success("🎉 우선순위 보안 이슈가 없습니다!")
        return
    
    # 상위 5개 우선순위 이슈 표시
    st.markdown("### 🚨 즉시 해결이 필요한 이슈 (상위 5개)")
    
    for i, issue in enumerate(priority_issues[:5], 1):
        with st.expander(f"{i}. {issue.get('description', '')[:80]}...", expanded=(i <= 2)):
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**서비스**: {issue.get('service', '').upper()}")
                st.markdown(f"**리소스**: {issue.get('resource', 'N/A')}")
                st.markdown(f"**설명**: {issue.get('description', '')}")
                
                # 권장 조치 표시
                remediation = get_detailed_remediation_steps(issue.get('type'), issue.get('resource'))
                if remediation:
                    st.markdown("**권장 조치**:")
                    st.markdown(f"- 예상 시간: {remediation.get('estimated_time', 'N/A')}")
                    st.markdown(f"- 난이도: {remediation.get('difficulty', 'N/A')}")
                    st.markdown(f"- 비용 영향: {remediation.get('cost_impact', 'N/A')}")
            
            with col2:
                risk_level = issue.get('risk_level', 'medium')
                severity_score = issue.get('severity_score', 0)
                
                if risk_level == 'high':
                    st.error(f"**위험도**: 높음")
                elif risk_level == 'medium':
                    st.warning(f"**위험도**: 중간")
                else:
                    st.info(f"**위험도**: 낮음")
                
                st.metric("심각도 점수", f"{severity_score:.1f}/10")

def show_dashboard_actions():
    """대시보드 액션 버튼들"""
    
    st.markdown("## ⚙️ 대시보드 액션")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔄 새로운 스캔 시작", use_container_width=True):
            st.session_state.scan_completed = False
            st.rerun()
    
    with col2:
        if st.button("📊 상세 보고서 생성", use_container_width=True):
            generate_detailed_report()
    
    with col3:
        if st.button("📋 권장사항 다운로드", use_container_width=True):
            download_recommendations()
    
    with col4:
        if st.button("🔧 설정 변경", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()

def get_score_color(score):
    """보안 점수에 따른 색상 반환"""
    if score >= 90:
        return "#28a745"  # 녹색
    elif score >= 70:
        return "#ffc107"  # 노란색
    elif score >= 50:
        return "#fd7e14"  # 주황색
    else:
        return "#dc3545"  # 빨간색

def get_score_grade(score):
    """보안 점수에 따른 등급 반환"""
    if score >= 90:
        return "우수"
    elif score >= 70:
        return "양호"
    elif score >= 50:
        return "보통"
    else:
        return "위험"

def generate_detailed_report():
    """상세 보고서 생성"""
    st.info("상세 보고서 생성 기능은 향후 구현 예정입니다.")

def download_recommendations():
    """권장사항 다운로드"""
    st.info("권장사항 다운로드 기능은 향후 구현 예정입니다.")

def create_security_score_chart(summary):
    """보안 점수 시각화 차트 생성"""
    
    security_score = summary.get('security_score', 0)
    
    # 게이지 차트 생성
    fig = px.pie(
        values=[security_score, 100-security_score],
        names=['보안 점수', '개선 여지'],
        title=f"전체 보안 점수: {security_score}/100",
        color_discrete_sequence=['#28a745' if security_score >= 70 else '#ffc107' if security_score >= 50 else '#dc3545', '#e9ecef']
    )
    
    fig.update_traces(
        textposition='inside', 
        textinfo='percent+label',
        hole=0.6
    )
    
    fig.update_layout(
        showlegend=False,
        height=300,
        annotations=[dict(text=f'{security_score}', x=0.5, y=0.5, font_size=40, showarrow=False)]
    )
    
    return fig

def create_issues_distribution_chart(summary):
    """보안 이슈 분포 차트 생성"""
    
    high_risk = summary.get('high_risk', 0)
    medium_risk = summary.get('medium_risk', 0)
    low_risk = summary.get('low_risk', 0)
    
    if high_risk == 0 and medium_risk == 0 and low_risk == 0:
        return None
    
    # 막대 차트 생성
    fig = px.bar(
        x=['높은 위험', '중간 위험', '낮은 위험'],
        y=[high_risk, medium_risk, low_risk],
        title="위험도별 이슈 분포",
        color=['높은 위험', '중간 위험', '낮은 위험'],
        color_discrete_map={
            '높은 위험': '#dc3545',
            '중간 위험': '#ffc107', 
            '낮은 위험': '#17a2b8'
        }
    )
    
    fig.update_layout(
        showlegend=False,
        height=400,
        xaxis_title="위험도",
        yaxis_title="이슈 수"
    )
    
    return fig

def create_service_health_chart(summary):
    """서비스별 보안 상태 차트 생성"""
    
    service_health = summary.get('service_health', {})
    
    if not service_health:
        return None
    
    services = list(service_health.keys())
    statuses = list(service_health.values())
    
    # 상태별 색상 매핑
    color_map = {
        'healthy': '#28a745',
        'caution': '#ffc107',
        'warning': '#fd7e14',
        'critical': '#dc3545',
        'error': '#6c757d'
    }
    
    colors = [color_map.get(status, '#6c757d') for status in statuses]
    
    # 수평 막대 차트 생성
    fig = px.bar(
        x=statuses,
        y=[s.upper() for s in services],
        orientation='h',
        title="서비스별 보안 상태",
        color=statuses,
        color_discrete_map=color_map
    )
    
    fig.update_layout(
        showlegend=False,
        height=300,
        xaxis_title="상태",
        yaxis_title="서비스"
    )
    
    return fig

def create_issue_categories_chart(summary):
    """이슈 카테고리별 분포 차트 생성"""
    
    issue_categories = summary.get('issue_categories', {})
    
    if not issue_categories:
        return None
    
    categories = []
    counts = []
    
    category_names = {
        'access_control': '접근 제어',
        'data_protection': '데이터 보호',
        'monitoring': '모니터링',
        'network_security': '네트워크 보안',
        'threat_detection': '위협 탐지',
        'compliance': '규정 준수'
    }
    
    for category, data in issue_categories.items():
        if data.get('count', 0) > 0:
            categories.append(category_names.get(category, category))
            counts.append(data.get('count', 0))
    
    if not categories:
        return None
    
    # 도넛 차트 생성
    fig = px.pie(
        values=counts,
        names=categories,
        title="보안 이슈 카테고리별 분포",
        hole=0.4
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(height=400)
    
    return fig

def create_cloudtrail_activity_chart(cloudtrail_data):
    """CloudTrail 활동 타임라인 차트 생성"""
    
    event_summary = cloudtrail_data.get('data', {}).get('event_summary', {})
    hourly_distribution = event_summary.get('hourly_distribution', {})
    
    if not hourly_distribution:
        return None
    
    hours = list(range(24))
    activities = [hourly_distribution.get(hour, 0) for hour in hours]
    
    # 시간별 활동 라인 차트 생성
    fig = px.line(
        x=hours,
        y=activities,
        title="최근 24시간 API 활동 분포",
        labels={'x': '시간 (24시간)', 'y': '이벤트 수'}
    )
    
    fig.update_traces(line_color='#17a2b8', line_width=3)
    fig.update_layout(
        height=300,
        xaxis=dict(tickmode='linear', tick0=0, dtick=2)
    )
    
    return fig

def create_compliance_status_chart(summary):
    """규정 준수 상태 차트 생성"""
    
    compliance_status = summary.get('compliance_status', {})
    
    if not compliance_status:
        return None
    
    compliance_data = []
    
    for standard, data in compliance_status.items():
        total = data.get('total', 0)
        passed = data.get('passed', 0)
        failed = data.get('failed', 0)
        
        if total > 0:
            compliance_rate = (passed / total) * 100
            compliance_data.append({
                'standard': data.get('name', standard),
                'compliance_rate': compliance_rate,
                'passed': passed,
                'failed': failed,
                'total': total
            })
    
    if not compliance_data:
        return None
    
    # 규정 준수율 막대 차트
    fig = px.bar(
        x=[d['standard'] for d in compliance_data],
        y=[d['compliance_rate'] for d in compliance_data],
        title="규정 준수 상태",
        labels={'x': '규정', 'y': '준수율 (%)'},
        color=[d['compliance_rate'] for d in compliance_data],
        color_continuous_scale=['red', 'yellow', 'green']
    )
    
    fig.update_layout(
        height=300,
        coloraxis_showscale=False
    )
    
    return fig

def show_enhanced_dashboard_with_charts():
    """차트가 포함된 향상된 대시보드 표시"""
    
    scan_results = st.session_state.get('scan_results', {})
    summary = scan_results.get('summary', {})
    
    # 차트 섹션 추가
    st.markdown("## 📈 보안 상태 시각화")
    
    # 첫 번째 행: 보안 점수와 이슈 분포
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        score_chart = create_security_score_chart(summary)
        if score_chart:
            st.plotly_chart(score_chart, use_container_width=True)
    
    with chart_col2:
        issues_chart = create_issues_distribution_chart(summary)
        if issues_chart:
            st.plotly_chart(issues_chart, use_container_width=True)
    
    # 두 번째 행: 서비스 상태와 카테고리 분포
    chart_col3, chart_col4 = st.columns(2)
    
    with chart_col3:
        service_chart = create_service_health_chart(summary)
        if service_chart:
            st.plotly_chart(service_chart, use_container_width=True)
    
    with chart_col4:
        category_chart = create_issue_categories_chart(summary)
        if category_chart:
            st.plotly_chart(category_chart, use_container_width=True)
    
    # 세 번째 행: CloudTrail 활동과 규정 준수
    chart_col5, chart_col6 = st.columns(2)
    
    with chart_col5:
        cloudtrail_chart = create_cloudtrail_activity_chart(scan_results.get('cloudtrail', {}))
        if cloudtrail_chart:
            st.plotly_chart(cloudtrail_chart, use_container_width=True)
    
    with chart_col6:
        compliance_chart = create_compliance_status_chart(summary)
        if compliance_chart:
            st.plotly_chart(compliance_chart, use_container_width=True)

def handle_aws_api_error(error, service_name="AWS"):
    """AWS API 오류를 사용자 친화적 메시지로 변환"""
    
    error_code = getattr(error, 'response', {}).get('Error', {}).get('Code', 'Unknown')
    error_message = getattr(error, 'response', {}).get('Error', {}).get('Message', str(error))
    
    user_friendly_messages = {
        'AccessDenied': {
            'title': '🚫 접근 권한 부족',
            'message': f'{service_name} 서비스에 접근할 권한이 없습니다.',
            'solutions': [
                '현재 사용 중인 IAM 사용자/역할에 필요한 권한이 있는지 확인하세요.',
                '관리자에게 적절한 읽기 권한 부여를 요청하세요.',
                '인스턴스 프로파일 사용 시 EC2 인스턴스에 올바른 역할이 연결되어 있는지 확인하세요.'
            ]
        },
        'InvalidUserID.NotFound': {
            'title': '❌ 유효하지 않은 사용자',
            'message': 'AWS 사용자 정보를 찾을 수 없습니다.',
            'solutions': [
                'Access Key ID가 올바른지 확인하세요.',
                '사용자가 삭제되었거나 비활성화되었을 수 있습니다.',
                'AWS 계정 관리자에게 문의하세요.'
            ]
        },
        'SignatureDoesNotMatch': {
            'title': '🔑 자격 증명 오류',
            'message': 'AWS 자격 증명이 올바르지 않습니다.',
            'solutions': [
                'Secret Access Key를 다시 확인하세요.',
                '복사/붙여넣기 시 공백이나 특수문자가 포함되지 않았는지 확인하세요.',
                '새로운 액세스 키를 생성해보세요.'
            ]
        },
        'TokenRefreshRequired': {
            'title': '⏰ 임시 자격 증명 만료',
            'message': '임시 자격 증명이 만료되었습니다.',
            'solutions': [
                '새로운 임시 자격 증명을 발급받으세요.',
                'AWS STS를 통해 새 토큰을 생성하세요.',
                '장기간 사용할 경우 IAM 사용자 자격 증명 사용을 고려하세요.'
            ]
        },
        'UnauthorizedOperation': {
            'title': '🚨 권한 없는 작업',
            'message': '해당 작업을 수행할 권한이 없습니다.',
            'solutions': [
                'IAM 정책에서 필요한 권한을 확인하세요.',
                '최소 권한 원칙에 따라 필요한 권한만 요청하세요.',
                '조직 정책(SCP)에 의해 차단되었을 수 있습니다.'
            ]
        },
        'RequestLimitExceeded': {
            'title': '⚡ 요청 한도 초과',
            'message': 'AWS API 요청 한도를 초과했습니다.',
            'solutions': [
                '잠시 후 다시 시도하세요.',
                '스캔 범위를 줄여서 실행해보세요.',
                'AWS 지원팀에 한도 증가를 요청하세요.'
            ]
        },
        'ServiceUnavailable': {
            'title': '🔧 서비스 일시 중단',
            'message': f'{service_name} 서비스가 일시적으로 사용할 수 없습니다.',
            'solutions': [
                '몇 분 후 다시 시도하세요.',
                'AWS 서비스 상태 페이지를 확인하세요.',
                '다른 리전에서 시도해보세요.'
            ]
        },
        'NetworkingError': {
            'title': '🌐 네트워크 연결 오류',
            'message': 'AWS 서비스에 연결할 수 없습니다.',
            'solutions': [
                '인터넷 연결을 확인하세요.',
                '방화벽이나 프록시 설정을 확인하세요.',
                'DNS 설정이 올바른지 확인하세요.'
            ]
        }
    }
    
    error_info = user_friendly_messages.get(error_code, {
        'title': f'⚠️ {service_name} 오류',
        'message': f'예상치 못한 오류가 발생했습니다: {error_code}',
        'solutions': [
            '잠시 후 다시 시도하세요.',
            '문제가 지속되면 AWS 지원팀에 문의하세요.',
            f'오류 코드: {error_code}'
        ]
    })
    
    return {
        'title': error_info['title'],
        'message': error_info['message'],
        'solutions': error_info['solutions'],
        'error_code': error_code,
        'original_message': error_message
    }

def display_error_message(error_info, show_details=False):
    """사용자 친화적 오류 메시지 표시"""
    
    st.error(f"**{error_info['title']}**")
    st.write(error_info['message'])
    
    if error_info['solutions']:
        st.markdown("**해결 방법:**")
        for i, solution in enumerate(error_info['solutions'], 1):
            st.markdown(f"{i}. {solution}")
    
    if show_details:
        with st.expander("🔍 기술적 세부사항"):
            st.code(f"오류 코드: {error_info['error_code']}")
            st.code(f"원본 메시지: {error_info['original_message']}")

def handle_network_error():
    """네트워크 연결 오류 처리"""
    
    st.error("🌐 **네트워크 연결 오류**")
    st.write("AWS 서비스에 연결할 수 없습니다.")
    
    st.markdown("**확인사항:**")
    st.markdown("1. 인터넷 연결이 정상인지 확인하세요.")
    st.markdown("2. 방화벽이나 프록시 설정을 확인하세요.")
    st.markdown("3. DNS 설정이 올바른지 확인하세요.")
    st.markdown("4. AWS 서비스 상태를 확인하세요: https://status.aws.amazon.com/")
    
    if st.button("🔄 연결 재시도"):
        st.rerun()

def handle_permission_error(service_name):
    """권한 부족 오류 처리"""
    
    st.warning(f"⚠️ **{service_name} 권한 부족**")
    st.write(f"{service_name} 서비스 스캔에 필요한 권한이 부족합니다.")
    
    required_permissions = get_required_permissions(service_name)
    
    if required_permissions:
        st.markdown("**필요한 권한:**")
        for permission in required_permissions:
            st.code(permission)
    
    st.markdown("**권장 조치:**")
    st.markdown("1. IAM 콘솔에서 현재 사용자/역할의 정책을 확인하세요.")
    st.markdown("2. 위의 권한을 포함한 정책을 연결하세요.")
    st.markdown("3. 또는 ReadOnlyAccess 정책을 임시로 연결해보세요.")

def get_required_permissions(service_name):
    """서비스별 필요한 권한 목록 반환"""
    
    permissions_map = {
        'IAM': [
            'iam:ListUsers',
            'iam:ListRoles', 
            'iam:ListGroups',
            'iam:GetUser',
            'iam:GetRole',
            'iam:GetAccountSummary',
            'iam:ListMFADevices',
            'iam:ListAccessKeys'
        ],
        'CloudTrail': [
            'cloudtrail:DescribeTrails',
            'cloudtrail:GetTrailStatus',
            'cloudtrail:LookupEvents'
        ],
        'S3': [
            's3:ListAllMyBuckets',
            's3:GetBucketLocation',
            's3:GetBucketAcl',
            's3:GetBucketPolicy',
            's3:GetBucketEncryption',
            's3:GetBucketVersioning'
        ],
        'GuardDuty': [
            'guardduty:ListDetectors',
            'guardduty:GetDetector',
            'guardduty:ListFindings',
            'guardduty:GetFindings'
        ],
        'WAF': [
            'wafv2:ListWebACLs',
            'wafv2:GetWebACL',
            'wafv2:ListResourcesForWebACL'
        ]
    }
    
    return permissions_map.get(service_name, [])

def create_error_recovery_suggestions(error_type, context=None):
    """오류 유형별 복구 제안 생성"""
    
    suggestions = {
        'authentication': [
            "자격 증명을 다시 입력해보세요.",
            "다른 IAM 사용자로 시도해보세요.",
            "인스턴스 프로파일 사용을 고려해보세요."
        ],
        'permission': [
            "관리자에게 필요한 권한 부여를 요청하세요.",
            "ReadOnlyAccess 정책 연결을 시도해보세요.",
            "특정 서비스만 스캔해보세요."
        ],
        'network': [
            "인터넷 연결을 확인하세요.",
            "VPN 연결을 확인하세요.",
            "다른 네트워크에서 시도해보세요."
        ],
        'service': [
            "잠시 후 다시 시도하세요.",
            "다른 리전을 선택해보세요.",
            "AWS 서비스 상태를 확인하세요."
        ]
    }
    
    return suggestions.get(error_type, ["문제가 지속되면 지원팀에 문의하세요."])

def log_error_for_debugging(error, context=None):
    """디버깅을 위한 오류 로깅"""
    
    import traceback
    
    error_details = {
        'timestamp': datetime.now().isoformat(),
        'error_type': type(error).__name__,
        'error_message': str(error),
        'context': context or {},
        'traceback': traceback.format_exc()
    }
    
    # 개발 모드에서만 상세 오류 정보 표시
    if st.session_state.get('debug_mode', False):
        with st.expander("🐛 디버그 정보"):
            st.json(error_details)
    
    return error_details

def safe_api_call(func, *args, **kwargs):
    """안전한 API 호출 래퍼"""
    
    try:
        return func(*args, **kwargs)
    except ClientError as e:
        error_info = handle_aws_api_error(e, kwargs.get('service_name', 'AWS'))
        return {'error': error_info, 'success': False}
    except Exception as e:
        error_details = log_error_for_debugging(e, {'function': func.__name__, 'args': args, 'kwargs': kwargs})
        return {'error': error_details, 'success': False}

def validate_user_input(input_data):
    """사용자 입력 검증"""
    
    validation_errors = []
    
    if 'account_id' in input_data:
        account_id = input_data['account_id']
        if not account_id.isdigit() or len(account_id) != 12:
            validation_errors.append("AWS 계정 ID는 12자리 숫자여야 합니다.")
    
    if 'access_key' in input_data:
        access_key = input_data['access_key']
        if not access_key.startswith('AKIA') or len(access_key) != 20:
            validation_errors.append("Access Key ID는 AKIA로 시작하는 20자리여야 합니다.")
    
    if 'region' in input_data:
        valid_regions = [
            'us-east-1', 'us-west-2', 'ap-northeast-2', 
            'eu-west-1', 'ap-southeast-1', 'ap-northeast-1'
        ]
        if input_data['region'] not in valid_regions:
            validation_errors.append(f"지원되지 않는 리전입니다. 지원 리전: {', '.join(valid_regions)}")
    
    return validation_errors

def show_loading_spinner(message="처리 중...", duration=None):
    """로딩 스피너 표시"""
    
    with st.spinner(message):
        if duration:
            import time
            time.sleep(duration)
        else:
            # 실제 작업이 완료될 때까지 대기
            pass

def create_progress_tracker(total_steps, current_step=0):
    """진행률 추적기 생성"""
    
    progress_data = {
        'total_steps': total_steps,
        'current_step': current_step,
        'progress_bar': None,
        'status_text': None,
        'step_details': None
    }
    
    return progress_data

def update_progress(progress_data, step, message, details=None):
    """진행률 업데이트"""
    
    progress_data['current_step'] = step
    progress_percentage = step / progress_data['total_steps']
    
    if progress_data['progress_bar'] is None:
        progress_data['progress_bar'] = st.progress(0)
        progress_data['status_text'] = st.empty()
        progress_data['step_details'] = st.empty()
    
    progress_data['progress_bar'].progress(progress_percentage)
    progress_data['status_text'].markdown(f"**{message}** ({step}/{progress_data['total_steps']})")
    
    if details:
        progress_data['step_details'].info(details)
    
    return progress_data

def show_scan_progress_enhanced(scan_steps, current_step_index):
    """향상된 스캔 진행 상태 표시"""
    
    st.markdown("### 🔄 스캔 진행 상황")
    
    # 전체 진행률
    total_progress = (current_step_index + 1) / len(scan_steps)
    st.progress(total_progress)
    
    # 현재 단계 정보
    if current_step_index < len(scan_steps):
        current_step = scan_steps[current_step_index]
        st.markdown(f"**현재 단계**: {current_step[1]}")
        st.info(f"단계 {current_step_index + 1}/{len(scan_steps)}: {current_step[0].upper()} 서비스 분석 중...")
    
    # 단계별 상태 표시
    cols = st.columns(len(scan_steps))
    
    for i, (service, description, _) in enumerate(scan_steps):
        with cols[i]:
            if i < current_step_index:
                st.success(f"✅ {service.upper()}")
                st.caption("완료")
            elif i == current_step_index:
                st.info(f"🔄 {service.upper()}")
                st.caption("진행 중")
            else:
                st.empty()
                st.caption("대기 중")

def show_data_loading_states():
    """데이터 로딩 상태별 표시"""
    
    loading_states = {
        'initializing': {
            'icon': '🔧',
            'message': '스캔 초기화 중...',
            'description': 'AWS 연결 및 권한을 확인하고 있습니다.'
        },
        'scanning': {
            'icon': '🔍',
            'message': '보안 스캔 진행 중...',
            'description': 'AWS 리소스를 분석하고 보안 이슈를 탐지하고 있습니다.'
        },
        'analyzing': {
            'icon': '🧠',
            'message': '결과 분석 중...',
            'description': '수집된 데이터를 분석하여 보안 위험을 평가하고 있습니다.'
        },
        'generating': {
            'icon': '📊',
            'message': '보고서 생성 중...',
            'description': '분석 결과를 바탕으로 대시보드와 권장사항을 생성하고 있습니다.'
        },
        'completing': {
            'icon': '✅',
            'message': '스캔 완료!',
            'description': '모든 분석이 완료되었습니다. 결과를 확인하세요.'
        }
    }
    
    return loading_states

def show_service_scan_progress(service_name, progress_percentage, current_action):
    """개별 서비스 스캔 진행률 표시"""
    
    service_icons = {
        'iam': '🔐',
        'cloudtrail': '📋',
        's3': '🗄️',
        'guardduty': '🛡️',
        'waf': '🌐'
    }
    
    icon = service_icons.get(service_name.lower(), '⚙️')
    
    st.markdown(f"### {icon} {service_name.upper()} 스캔")
    
    # 서비스별 진행률 바
    progress_bar = st.progress(progress_percentage / 100)
    st.markdown(f"**현재 작업**: {current_action}")
    st.caption(f"진행률: {progress_percentage:.1f}%")
    
    return progress_bar

def create_real_time_status_display():
    """실시간 상태 표시 컨테이너 생성"""
    
    status_container = st.container()
    
    with status_container:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status_metric = st.empty()
        with col2:
            progress_metric = st.empty()
        with col3:
            time_metric = st.empty()
        
        status_message = st.empty()
        detailed_progress = st.empty()
    
    return {
        'container': status_container,
        'status_metric': status_metric,
        'progress_metric': progress_metric,
        'time_metric': time_metric,
        'status_message': status_message,
        'detailed_progress': detailed_progress
    }

def update_real_time_status(display_elements, status, progress, elapsed_time, message, details=None):
    """실시간 상태 업데이트"""
    
    display_elements['status_metric'].metric("상태", status)
    display_elements['progress_metric'].metric("진행률", f"{progress:.1f}%")
    display_elements['time_metric'].metric("경과 시간", f"{elapsed_time:.1f}초")
    
    display_elements['status_message'].info(message)
    
    if details:
        display_elements['detailed_progress'].markdown(details)

def show_scan_completion_summary(scan_results, total_time):
    """스캔 완료 요약 표시"""
    
    st.success("🎉 **보안 스캔이 성공적으로 완료되었습니다!**")
    
    summary = scan_results.get('summary', {})
    
    # 완료 요약 메트릭
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("총 소요 시간", f"{total_time:.1f}초")
    
    with col2:
        services_scanned = summary.get('services_scanned', 0)
        st.metric("스캔 완료 서비스", f"{services_scanned}/5")
    
    with col3:
        total_issues = summary.get('total_issues', 0)
        st.metric("발견된 이슈", total_issues)
    
    with col4:
        security_score = summary.get('security_score', 0)
        st.metric("보안 점수", f"{security_score}/100")
    
    # 다음 단계 안내
    st.markdown("### 📋 다음 단계")
    st.info("아래 버튼을 클릭하여 상세한 보안 분석 결과를 확인하세요.")
    
    if st.button("📊 대시보드 보기", type="primary", use_container_width=True):
        st.rerun()

def show_error_recovery_options(error_info):
    """오류 복구 옵션 표시"""
    
    st.markdown("### 🔧 복구 옵션")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔄 다시 시도", use_container_width=True):
            st.rerun()
    
    with col2:
        if st.button("⚙️ 설정 변경", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()
    
    with col3:
        if st.button("📞 지원 요청", use_container_width=True):
            show_support_contact_info()

def show_support_contact_info():
    """지원 연락처 정보 표시"""
    
    st.markdown("### 📞 지원 요청")
    
    st.info("""
    **기술 지원이 필요하신가요?**
    
    다음 정보를 포함하여 지원팀에 문의하세요:
    - 발생한 오류 메시지
    - 사용 중인 AWS 리전
    - 스캔하려던 서비스
    - 오류 발생 시간
    """)
    
    st.markdown("**유용한 링크:**")
    st.markdown("- [AWS 지원 센터](https://console.aws.amazon.com/support/)")
    st.markdown("- [AWS 서비스 상태](https://status.aws.amazon.com/)")
    st.markdown("- [AWS 문서](https://docs.aws.amazon.com/)")

def create_loading_animation():
    """로딩 애니메이션 생성"""
    
    loading_messages = [
        "🔍 AWS 리소스 검색 중...",
        "🔐 보안 설정 분석 중...",
        "📊 데이터 수집 중...",
        "🧠 위험 요소 평가 중...",
        "📋 권장사항 생성 중...",
        "✨ 결과 정리 중..."
    ]
    
    return loading_messages

def show_progress_with_eta(current_step, total_steps, start_time):
    """예상 완료 시간과 함께 진행률 표시"""
    
    elapsed_time = (datetime.now() - start_time).total_seconds()
    progress_percentage = current_step / total_steps
    
    if progress_percentage > 0:
        estimated_total_time = elapsed_time / progress_percentage
        eta = estimated_total_time - elapsed_time
        eta_minutes = int(eta // 60)
        eta_seconds = int(eta % 60)
        
        st.progress(progress_percentage)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("진행률", f"{progress_percentage:.1%}")
        with col2:
            st.metric("경과 시간", f"{int(elapsed_time)}초")
        with col3:
            if eta > 0:
                st.metric("예상 완료", f"{eta_minutes}분 {eta_seconds}초")
            else:
                st.metric("예상 완료", "곧 완료")
    else:
        st.progress(0)
        st.info("스캔을 시작하는 중...")

if __name__ == "__main__":
    main()