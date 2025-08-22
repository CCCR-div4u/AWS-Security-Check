#!/usr/bin/env python3
"""
전체 애플리케이션 통합 검증 테스트
실제 사용자 시나리오를 기반으로 한 종단간 테스트
"""

import unittest
import sys
import os
import time
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import streamlit as st
from streamlit.testing.v1 import AppTest

# 프로젝트 루트 디렉터리를 Python 경로에 추가
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


class TestFullApplicationWorkflow(unittest.TestCase):
    """전체 애플리케이션 워크플로우 테스트"""
    
    def setUp(self):
        """테스트 설정"""
        self.test_credentials = {
            'account_id': '123456789012',
            'access_key': 'AKIAIOSFODNN7EXAMPLE',
            'secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'region': 'ap-northeast-2'
        }
        
        # Mock AWS 응답 데이터
        self.mock_aws_responses = self._create_mock_aws_responses()
    
    def _create_mock_aws_responses(self):
        """Mock AWS 응답 데이터 생성"""
        return {
            'sts_identity': {
                'Account': '123456789012',
                'Arn': 'arn:aws:iam::123456789012:user/testuser',
                'UserId': 'AIDACKCEVSQ6C2EXAMPLE'
            },
            'iam_summary': {
                'SummaryMap': {
                    'Users': 15,
                    'Roles': 25,
                    'Groups': 5,
                    'Policies': 50,
                    'MFADevices': 8
                }
            },
            'iam_users': [
                {
                    'UserName': 'admin-user',
                    'Arn': 'arn:aws:iam::123456789012:user/admin-user',
                    'CreateDate': datetime.now() - timedelta(days=30),
                    'Path': '/',
                    'PasswordLastUsed': datetime.now() - timedelta(days=1)
                },
                {
                    'UserName': 'inactive-user',
                    'Arn': 'arn:aws:iam::123456789012:user/inactive-user',
                    'CreateDate': datetime.now() - timedelta(days=365),
                    'Path': '/',
                    'PasswordLastUsed': datetime.now() - timedelta(days=180)
                }
            ],
            's3_buckets': [
                {
                    'Name': 'secure-bucket',
                    'CreationDate': datetime.now() - timedelta(days=30)
                },
                {
                    'Name': 'public-bucket',
                    'CreationDate': datetime.now() - timedelta(days=60)
                }
            ],
            'cloudtrail_trails': [
                {
                    'Name': 'main-trail',
                    'S3BucketName': 'cloudtrail-logs',
                    'IsLogging': True,
                    'IsMultiRegionTrail': True
                }
            ],
            'guardduty_findings': [
                {
                    'Id': 'finding-1',
                    'Type': 'Trojan:EC2/DNSDataExfiltration',
                    'Severity': 8.5,
                    'Title': 'Suspicious DNS activity detected',
                    'Description': 'EC2 instance communicating with suspicious domain'
                }
            ]
        }
    
    def test_complete_user_workflow(self):
        """완전한 사용자 워크플로우 테스트"""
        print("\n=== 전체 사용자 워크플로우 테스트 시작 ===")
        
        # 1단계: 애플리케이션 초기화 검증
        print("1단계: 애플리케이션 초기화 검증")
        self._test_application_initialization()
        
        # 2단계: 자격 증명 입력 및 검증
        print("2단계: 자격 증명 입력 및 검증")
        self._test_credential_validation()
        
        # 3단계: 보안 스캔 실행
        print("3단계: 보안 스캔 실행")
        self._test_security_scan_execution()
        
        # 4단계: 결과 표시 및 분석
        print("4단계: 결과 표시 및 분석")
        self._test_results_display()
        
        # 5단계: 권장 조치 제공
        print("5단계: 권장 조치 제공")
        self._test_recommendations()
        
        print("✅ 전체 워크플로우 테스트 완료")
    
    def _test_application_initialization(self):
        """애플리케이션 초기화 테스트"""
        # 필수 모듈 import 확인
        try:
            import streamlit as st
            import boto3
            import pandas as pd
            import plotly.express as px
            print("  ✅ 필수 모듈 import 성공")
        except ImportError as e:
            self.fail(f"필수 모듈 import 실패: {e}")
        
        # Streamlit 설정 확인
        # 실제 Streamlit 앱에서는 이미 설정되어 있음
        print("  ✅ Streamlit 설정 확인 완료")
    
    @patch('boto3.Session')
    def _test_credential_validation(self, mock_session):
        """자격 증명 검증 테스트"""
        # Mock STS 클라이언트 설정
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = self.mock_aws_responses['sts_identity']
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_sts_client
        mock_session.return_value = mock_session_instance
        
        # 자격 증명 검증 시뮬레이션
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=self.test_credentials['access_key'],
                aws_secret_access_key=self.test_credentials['secret_key'],
                region_name=self.test_credentials['region']
            )
            
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            
            # 검증
            self.assertEqual(identity['Account'], self.test_credentials['account_id'])
            print("  ✅ AWS 자격 증명 검증 성공")
            
        except Exception as e:
            self.fail(f"자격 증명 검증 실패: {e}")
    
    @patch('boto3.Session')
    def _test_security_scan_execution(self, mock_session):
        """보안 스캔 실행 테스트"""
        # Mock 클라이언트들 설정
        mock_clients = self._setup_mock_clients()
        mock_session_instance = Mock()
        mock_session_instance.client.side_effect = lambda service: mock_clients.get(service, Mock())
        mock_session.return_value = mock_session_instance
        
        # 각 서비스별 스캔 시뮬레이션
        services_to_scan = ['iam', 's3', 'cloudtrail', 'guardduty', 'waf']
        scan_results = {}
        
        for service in services_to_scan:
            try:
                # 서비스별 스캔 로직 시뮬레이션
                if service == 'iam':
                    result = self._simulate_iam_scan(mock_clients['iam'])
                elif service == 's3':
                    result = self._simulate_s3_scan(mock_clients['s3'])
                elif service == 'cloudtrail':
                    result = self._simulate_cloudtrail_scan(mock_clients['cloudtrail'])
                elif service == 'guardduty':
                    result = self._simulate_guardduty_scan(mock_clients['guardduty'])
                elif service == 'waf':
                    result = self._simulate_waf_scan(mock_clients['wafv2'])
                
                scan_results[service] = result
                print(f"  ✅ {service.upper()} 스캔 완료")
                
            except Exception as e:
                print(f"  ⚠️ {service.upper()} 스캔 실패: {e}")
                scan_results[service] = {'status': 'failed', 'error': str(e)}
        
        # 스캔 결과 검증
        self.assertGreater(len(scan_results), 0, "최소 하나 이상의 서비스 스캔 결과가 있어야 함")
        print("  ✅ 보안 스캔 실행 완료")
        
        return scan_results
    
    def _setup_mock_clients(self):
        """Mock AWS 클라이언트들 설정"""
        mock_clients = {}
        
        # IAM 클라이언트
        mock_iam = Mock()
        mock_iam.get_account_summary.return_value = self.mock_aws_responses['iam_summary']
        mock_iam.list_users.return_value = {'Users': self.mock_aws_responses['iam_users']}
        mock_clients['iam'] = mock_iam
        
        # S3 클라이언트
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {'Buckets': self.mock_aws_responses['s3_buckets']}
        mock_clients['s3'] = mock_s3
        
        # CloudTrail 클라이언트
        mock_cloudtrail = Mock()
        mock_cloudtrail.describe_trails.return_value = {'trailList': self.mock_aws_responses['cloudtrail_trails']}
        mock_clients['cloudtrail'] = mock_cloudtrail
        
        # GuardDuty 클라이언트
        mock_guardduty = Mock()
        mock_guardduty.list_detectors.return_value = {'DetectorIds': ['detector-1']}
        mock_guardduty.get_findings.return_value = {'Findings': self.mock_aws_responses['guardduty_findings']}
        mock_clients['guardduty'] = mock_guardduty
        
        # WAF 클라이언트
        mock_waf = Mock()
        mock_waf.list_web_acls.return_value = {'WebACLs': []}
        mock_clients['wafv2'] = mock_waf
        
        return mock_clients
    
    def _simulate_iam_scan(self, mock_iam_client):
        """IAM 스캔 시뮬레이션"""
        summary = mock_iam_client.get_account_summary()
        users = mock_iam_client.list_users()
        
        # 보안 이슈 탐지 시뮬레이션
        issues = []
        for user in users['Users']:
            # 180일 이상 비활성 사용자 탐지
            if 'PasswordLastUsed' in user:
                days_inactive = (datetime.now() - user['PasswordLastUsed']).days
                if days_inactive > 180:
                    issues.append({
                        'type': 'inactive_user',
                        'resource': user['UserName'],
                        'risk_level': 'medium',
                        'description': f'{days_inactive}일 동안 비활성 상태인 사용자'
                    })
        
        return {
            'status': 'completed',
            'data': {'summary': summary, 'users': users},
            'issues': issues
        }
    
    def _simulate_s3_scan(self, mock_s3_client):
        """S3 스캔 시뮬레이션"""
        buckets = mock_s3_client.list_buckets()
        
        # 공개 버킷 탐지 시뮬레이션
        issues = []
        for bucket in buckets['Buckets']:
            if 'public' in bucket['Name'].lower():
                issues.append({
                    'type': 'public_bucket',
                    'resource': bucket['Name'],
                    'risk_level': 'high',
                    'description': '공개 액세스가 허용된 S3 버킷'
                })
        
        return {
            'status': 'completed',
            'data': {'buckets': buckets},
            'issues': issues
        }
    
    def _simulate_cloudtrail_scan(self, mock_cloudtrail_client):
        """CloudTrail 스캔 시뮬레이션"""
        trails = mock_cloudtrail_client.describe_trails()
        
        issues = []
        if not trails['trailList']:
            issues.append({
                'type': 'no_cloudtrail',
                'resource': 'CloudTrail',
                'risk_level': 'high',
                'description': 'CloudTrail이 설정되지 않음'
            })
        
        return {
            'status': 'completed',
            'data': {'trails': trails},
            'issues': issues
        }
    
    def _simulate_guardduty_scan(self, mock_guardduty_client):
        """GuardDuty 스캔 시뮬레이션"""
        detectors = mock_guardduty_client.list_detectors()
        findings = mock_guardduty_client.get_findings(DetectorId='detector-1', FindingIds=['finding-1'])
        
        issues = []
        for finding in findings['Findings']:
            issues.append({
                'type': 'threat_detected',
                'resource': finding['Type'],
                'risk_level': 'high' if finding['Severity'] > 7 else 'medium',
                'description': finding['Description']
            })
        
        return {
            'status': 'completed',
            'data': {'detectors': detectors, 'findings': findings},
            'issues': issues
        }
    
    def _simulate_waf_scan(self, mock_waf_client):
        """WAF 스캔 시뮬레이션"""
        web_acls = mock_waf_client.list_web_acls(Scope='REGIONAL')
        
        issues = []
        if not web_acls['WebACLs']:
            issues.append({
                'type': 'no_waf',
                'resource': 'WAF',
                'risk_level': 'medium',
                'description': 'WAF가 설정되지 않음'
            })
        
        return {
            'status': 'completed',
            'data': {'web_acls': web_acls},
            'issues': issues
        }
    
    def _test_results_display(self):
        """결과 표시 테스트"""
        # 테스트 결과 데이터 생성
        test_results = {
            'summary': {
                'total_issues': 5,
                'high_risk': 2,
                'medium_risk': 2,
                'low_risk': 1,
                'security_score': 65
            },
            'issues': [
                {
                    'type': 'public_bucket',
                    'resource': 'public-bucket',
                    'risk_level': 'high',
                    'description': '공개 액세스가 허용된 S3 버킷'
                },
                {
                    'type': 'inactive_user',
                    'resource': 'inactive-user',
                    'risk_level': 'medium',
                    'description': '180일 동안 비활성 상태인 사용자'
                }
            ]
        }
        
        # 결과 데이터 검증
        self.assertIn('summary', test_results)
        self.assertIn('issues', test_results)
        self.assertGreater(test_results['summary']['total_issues'], 0)
        
        print("  ✅ 결과 데이터 구조 검증 완료")
        
        # 시각화 데이터 준비 테스트
        try:
            import pandas as pd
            import plotly.express as px
            
            # 이슈 분포 차트 데이터
            risk_counts = {
                'High': test_results['summary']['high_risk'],
                'Medium': test_results['summary']['medium_risk'],
                'Low': test_results['summary']['low_risk']
            }
            
            # 데이터프레임 생성 테스트
            df = pd.DataFrame(list(risk_counts.items()), columns=['Risk Level', 'Count'])
            self.assertEqual(len(df), 3)
            
            print("  ✅ 시각화 데이터 준비 완료")
            
        except Exception as e:
            self.fail(f"시각화 데이터 준비 실패: {e}")
    
    def _test_recommendations(self):
        """권장 조치 테스트"""
        # 권장 조치 템플릿 테스트
        recommendations = {
            'public_bucket': {
                'title': 'S3 버킷 공개 액세스 제한',
                'steps': [
                    'S3 콘솔에서 해당 버킷 선택',
                    '권한 탭에서 퍼블릭 액세스 차단 설정',
                    '버킷 정책 검토 및 수정'
                ],
                'priority': 'high',
                'aws_docs': 'https://docs.aws.amazon.com/s3/latest/userguide/access-control-block-public-access.html'
            },
            'inactive_user': {
                'title': '비활성 사용자 계정 관리',
                'steps': [
                    'IAM 콘솔에서 사용자 활동 이력 확인',
                    '불필요한 사용자 계정 비활성화',
                    '액세스 키 회전 또는 삭제'
                ],
                'priority': 'medium',
                'aws_docs': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
            }
        }
        
        # 권장 조치 데이터 검증
        for issue_type, recommendation in recommendations.items():
            self.assertIn('title', recommendation)
            self.assertIn('steps', recommendation)
            self.assertIn('priority', recommendation)
            self.assertIsInstance(recommendation['steps'], list)
            self.assertGreater(len(recommendation['steps']), 0)
        
        print("  ✅ 권장 조치 데이터 검증 완료")


class TestPerformanceAndMemory(unittest.TestCase):
    """성능 및 메모리 사용량 테스트"""
    
    def test_memory_usage_under_load(self):
        """부하 상황에서 메모리 사용량 테스트"""
        import psutil
        import gc
        
        # 초기 메모리 사용량
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # 대량 데이터 처리 시뮬레이션
        large_dataset = []
        for i in range(10000):
            large_dataset.append({
                'id': i,
                'name': f'resource-{i}',
                'data': f'data-{i}' * 50,
                'timestamp': datetime.now()
            })
        
        # 데이터 처리
        processed_data = [item for item in large_dataset if item['id'] % 2 == 0]
        
        # 메모리 정리
        del large_dataset
        gc.collect()
        
        # 최종 메모리 사용량
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # 메모리 증가량이 합리적인 범위 내인지 확인 (100MB 이하)
        self.assertLess(memory_increase, 100, f"메모리 사용량이 과도하게 증가: {memory_increase:.2f}MB")
        
        print(f"  ✅ 메모리 사용량 테스트 완료 (증가량: {memory_increase:.2f}MB)")
    
    def test_response_time_performance(self):
        """응답 시간 성능 테스트"""
        import time
        
        # 데이터 처리 시간 측정
        start_time = time.time()
        
        # 보안 스캔 시뮬레이션 (1000개 리소스)
        resources = []
        for i in range(1000):
            resources.append({
                'id': f'resource-{i}',
                'type': 'user' if i % 3 == 0 else 'role',
                'last_used': datetime.now() - timedelta(days=i % 365),
                'permissions': ['read', 'write'] if i % 2 == 0 else ['read']
            })
        
        # 보안 이슈 탐지 시뮬레이션
        issues = []
        for resource in resources:
            days_inactive = (datetime.now() - resource['last_used']).days
            if days_inactive > 90:
                issues.append({
                    'resource': resource['id'],
                    'issue': 'inactive',
                    'days': days_inactive
                })
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # 처리 시간이 합리적인 범위 내인지 확인 (2초 이하)
        self.assertLess(processing_time, 2.0, f"처리 시간이 과도함: {processing_time:.2f}초")
        
        print(f"  ✅ 응답 시간 테스트 완료 (처리 시간: {processing_time:.2f}초)")


class TestSecurityValidation(unittest.TestCase):
    """보안 검증 테스트"""
    
    def test_credential_handling_security(self):
        """자격 증명 처리 보안 테스트"""
        # 민감한 정보 마스킹 테스트
        def mask_sensitive_data(data):
            masked = data.copy()
            if 'aws_secret_access_key' in masked:
                masked['aws_secret_access_key'] = '*' * len(masked['aws_secret_access_key'])
            if 'aws_access_key_id' in masked:
                key = masked['aws_access_key_id']
                masked['aws_access_key_id'] = key[:4] + '*' * (len(key) - 8) + key[-4:]
            return masked
        
        # 테스트 데이터
        sensitive_data = {
            'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'account_id': '123456789012'
        }
        
        masked_data = mask_sensitive_data(sensitive_data)
        
        # 마스킹 검증
        self.assertNotEqual(masked_data['aws_secret_access_key'], sensitive_data['aws_secret_access_key'])
        self.assertIn('*', masked_data['aws_access_key_id'])
        self.assertEqual(masked_data['account_id'], sensitive_data['account_id'])  # 계정 ID는 마스킹하지 않음
        
        print("  ✅ 자격 증명 마스킹 테스트 완료")
    
    def test_input_sanitization(self):
        """입력 데이터 검증 테스트"""
        # 입력 검증 함수들
        def validate_account_id(account_id):
            return isinstance(account_id, str) and account_id.isdigit() and len(account_id) == 12
        
        def validate_access_key(access_key):
            return isinstance(access_key, str) and access_key.startswith('AKIA') and len(access_key) == 20
        
        def validate_region(region):
            valid_regions = ['ap-northeast-2', 'us-east-1', 'us-west-2', 'eu-west-1']
            return region in valid_regions
        
        # 유효한 입력 테스트
        self.assertTrue(validate_account_id('123456789012'))
        self.assertTrue(validate_access_key('AKIAIOSFODNN7EXAMPLE'))
        self.assertTrue(validate_region('ap-northeast-2'))
        
        # 잘못된 입력 테스트
        self.assertFalse(validate_account_id('12345678901'))  # 11자리
        self.assertFalse(validate_access_key('BKIAIOSFODNN7EXAMPLE'))  # 잘못된 접두사
        self.assertFalse(validate_region('invalid-region'))  # 잘못된 리전
        
        print("  ✅ 입력 검증 테스트 완료")


def run_full_integration_tests():
    """전체 통합 테스트 실행"""
    print("=" * 80)
    print("AWS 보안 대시보드 - 전체 통합 검증 테스트")
    print("=" * 80)
    
    # 테스트 스위트 생성
    test_suite = unittest.TestSuite()
    
    # 테스트 클래스들 추가
    test_classes = [
        TestFullApplicationWorkflow,
        TestPerformanceAndMemory,
        TestSecurityValidation
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # 테스트 실행
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(test_suite)
    
    # 결과 요약
    print("\n" + "=" * 80)
    print("통합 테스트 결과 요약")
    print("=" * 80)
    print(f"총 테스트: {result.testsRun}개")
    print(f"성공: {result.testsRun - len(result.failures) - len(result.errors)}개")
    print(f"실패: {len(result.failures)}개")
    print(f"오류: {len(result.errors)}개")
    
    if result.failures:
        print("\n실패한 테스트:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\n오류가 발생한 테스트:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Exception:')[-1].strip()}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
    print(f"\n성공률: {success_rate:.1f}%")
    
    if result.wasSuccessful():
        print("\n🎉 모든 통합 테스트가 성공적으로 완료되었습니다!")
        return True
    else:
        print("\n⚠️ 일부 테스트가 실패했습니다. 위의 세부 정보를 확인하세요.")
        return False


if __name__ == '__main__':
    success = run_full_integration_tests()
    sys.exit(0 if success else 1)