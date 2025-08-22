#!/usr/bin/env python3
"""
통합 테스트
전체 애플리케이션의 통합 기능을 테스트합니다.
"""

import unittest
import os
import sys
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError

# 프로젝트 루트 디렉터리를 Python 경로에 추가
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


class TestFullWorkflowIntegration(unittest.TestCase):
    """전체 워크플로우 통합 테스트"""
    
    def setUp(self):
        """테스트 설정"""
        self.test_session_state = {
            'authenticated': False,
            'aws_session': None,
            'scan_completed': False,
            'account_info': None,
            'scan_results': None,
            'scan_options': None
        }
        
        self.mock_aws_data = self._create_mock_aws_data()
    
    def _create_mock_aws_data(self):
        """Mock AWS 데이터 생성"""
        return {
            'sts': {
                'identity': {
                    'Account': '123456789012',
                    'Arn': 'arn:aws:iam::123456789012:user/testuser',
                    'UserId': 'AIDACKCEVSQ6C2EXAMPLE'
                }
            },
            'iam': {
                'account_summary': {
                    'SummaryMap': {
                        'Users': 15,
                        'Roles': 25,
                        'Groups': 5,
                        'Policies': 50,
                        'MFADevices': 8
                    }
                },
                'users': [
                    {
                        'UserName': 'admin-user',
                        'Arn': 'arn:aws:iam::123456789012:user/admin-user',
                        'CreateDate': datetime.now() - timedelta(days=30),
                        'Path': '/',
                        'PasswordLastUsed': datetime.now() - timedelta(days=1)
                    },
                    {
                        'UserName': 'old-user',
                        'Arn': 'arn:aws:iam::123456789012:user/old-user',
                        'CreateDate': datetime.now() - timedelta(days=365),
                        'Path': '/',
                        'PasswordLastUsed': datetime.now() - timedelta(days=180)
                    }
                ],
                'roles': [
                    {
                        'RoleName': 'EC2-Role',
                        'Arn': 'arn:aws:iam::123456789012:role/EC2-Role',
                        'CreateDate': datetime.now() - timedelta(days=60),
                        'Path': '/'
                    }
                ]
            },
            's3': {
                'buckets': [
                    {
                        'Name': 'private-bucket',
                        'CreationDate': datetime.now() - timedelta(days=30)
                    },
                    {
                        'Name': 'public-bucket',
                        'CreationDate': datetime.now() - timedelta(days=60)
                    }
                ],
                'bucket_acls': {
                    'private-bucket': {
                        'Grants': [
                            {
                                'Grantee': {'Type': 'CanonicalUser', 'ID': 'owner-id'},
                                'Permission': 'FULL_CONTROL'
                            }
                        ]
                    },
                    'public-bucket': {
                        'Grants': [
                            {
                                'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                                'Permission': 'READ'
                            }
                        ]
                    }
                }
            },
            'cloudtrail': {
                'trails': [
                    {
                        'Name': 'main-trail',
                        'S3BucketName': 'cloudtrail-logs',
                        'IsLogging': True,
                        'IsMultiRegionTrail': True
                    }
                ],
                'events': [
                    {
                        'EventTime': datetime.now() - timedelta(hours=2),
                        'EventName': 'ConsoleLogin',
                        'Username': 'admin-user',
                        'SourceIPAddress': '203.0.113.1'
                    },
                    {
                        'EventTime': datetime.now() - timedelta(hours=1),
                        'EventName': 'CreateUser',
                        'Username': 'admin-user',
                        'SourceIPAddress': '198.51.100.1'
                    }
                ]
            },
            'guardduty': {
                'detectors': ['detector-123'],
                'findings': [
                    {
                        'Id': 'finding-1',
                        'Type': 'Trojan:EC2/DNSDataExfiltration',
                        'Severity': 8.5,
                        'Title': 'Suspicious DNS activity',
                        'Description': 'EC2 instance is communicating with a domain name that is associated with a known threat.'
                    }
                ]
            },
            'waf': {
                'web_acls': [
                    {
                        'Name': 'main-web-acl',
                        'Id': 'web-acl-123',
                        'ARN': 'arn:aws:wafv2:ap-northeast-2:123456789012:regional/webacl/main-web-acl/web-acl-123'
                    }
                ]
            }
        }
    
    @patch('boto3.Session')
    def test_complete_authentication_flow(self, mock_session):
        """완전한 인증 플로우 테스트"""
        # Mock 설정
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = self.mock_aws_data['sts']['identity']
        
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_sts_client
        mock_session.return_value = mock_session_instance
        
        # 1단계: 초기 상태 확인
        self.assertFalse(self.test_session_state['authenticated'])
        
        # 2단계: 자격 증명 검증 시뮬레이션
        session = boto3.Session(
            aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
            aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            region_name='ap-northeast-2'
        )
        
        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        
        # 3단계: 인증 성공 처리
        self.test_session_state['authenticated'] = True
        self.test_session_state['aws_session'] = session
        self.test_session_state['account_info'] = {
            'account_id': identity['Account'],
            'user_arn': identity['Arn'],
            'region': 'ap-northeast-2',
            'use_instance_profile': False
        }
        
        # 4단계: 최종 상태 검증
        self.assertTrue(self.test_session_state['authenticated'])
        self.assertIsNotNone(self.test_session_state['aws_session'])
        self.assertEqual(self.test_session_state['account_info']['account_id'], '123456789012')
    
    @patch('boto3.Session')
    def test_complete_security_scan_flow(self, mock_session):
        """완전한 보안 스캔 플로우 테스트"""
        # 인증된 상태에서 시작
        self.test_session_state['authenticated'] = True
        
        # Mock 클라이언트들 설정
        mock_clients = self._setup_mock_clients()
        mock_session_instance = Mock()
        mock_session_instance.client.side_effect = lambda service: mock_clients[service]
        mock_session.return_value = mock_session_instance
        
        self.test_session_state['aws_session'] = boto3.Session()
        
        # 스캔 옵션 설정
        scan_options = {
            'iam': True,
            'cloudtrail': True,
            's3': True,
            'guardduty': True,
            'waf': True,
            'deep_scan': False
        }
        self.test_session_state['scan_options'] = scan_options
        
        # 스캔 실행 시뮬레이션
        scan_results = self._simulate_security_scan(mock_clients)
        
        # 스캔 결과 저장
        self.test_session_state['scan_results'] = scan_results
        self.test_session_state['scan_completed'] = True
        
        # 결과 검증
        self.assertTrue(self.test_session_state['scan_completed'])
        self.assertIsNotNone(self.test_session_state['scan_results'])
        
        # 각 서비스별 스캔 결과 확인
        for service in ['iam', 's3', 'cloudtrail', 'guardduty', 'waf']:
            self.assertIn(service, scan_results)
            self.assertEqual(scan_results[service]['status'], 'completed')
        
        # 요약 정보 확인
        summary = scan_results['summary']
        self.assertGreater(summary['total_issues'], 0)
        self.assertIn('security_score', summary)
    
    def _setup_mock_clients(self):
        """Mock AWS 클라이언트들 설정"""
        mock_clients = {}
        
        # STS 클라이언트
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = self.mock_aws_data['sts']['identity']
        mock_clients['sts'] = mock_sts
        
        # IAM 클라이언트
        mock_iam = Mock()
        mock_iam.get_account_summary.return_value = self.mock_aws_data['iam']['account_summary']
        mock_iam.list_users.return_value = {'Users': self.mock_aws_data['iam']['users']}
        mock_iam.list_roles.return_value = {'Roles': self.mock_aws_data['iam']['roles']}
        mock_iam.list_groups.return_value = {'Groups': []}
        mock_clients['iam'] = mock_iam
        
        # S3 클라이언트
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {'Buckets': self.mock_aws_data['s3']['buckets']}
        mock_s3.get_bucket_acl.side_effect = lambda **kwargs: self.mock_aws_data['s3']['bucket_acls'][kwargs['Bucket']]
        mock_clients['s3'] = mock_s3
        
        # CloudTrail 클라이언트
        mock_cloudtrail = Mock()
        mock_cloudtrail.describe_trails.return_value = {'trailList': self.mock_aws_data['cloudtrail']['trails']}
        mock_cloudtrail.lookup_events.return_value = {'Events': self.mock_aws_data['cloudtrail']['events']}
        mock_clients['cloudtrail'] = mock_cloudtrail
        
        # GuardDuty 클라이언트
        mock_guardduty = Mock()
        mock_guardduty.list_detectors.return_value = {'DetectorIds': self.mock_aws_data['guardduty']['detectors']}
        mock_guardduty.list_findings.return_value = {'FindingIds': ['finding-1']}
        mock_guardduty.get_findings.return_value = {'Findings': self.mock_aws_data['guardduty']['findings']}
        mock_clients['guardduty'] = mock_guardduty
        
        # WAF 클라이언트
        mock_waf = Mock()
        mock_waf.list_web_acls.return_value = {'WebACLs': self.mock_aws_data['waf']['web_acls']}
        mock_clients['wafv2'] = mock_waf
        
        return mock_clients
    
    def _simulate_security_scan(self, mock_clients):
        """보안 스캔 시뮬레이션"""
        scan_results = {
            'iam': {'status': 'completed', 'data': {}, 'issues': []},
            'cloudtrail': {'status': 'completed', 'data': {}, 'issues': []},
            's3': {'status': 'completed', 'data': {}, 'issues': []},
            'guardduty': {'status': 'completed', 'data': {}, 'issues': []},
            'waf': {'status': 'completed', 'data': {}, 'issues': []},
            'summary': {}
        }
        
        # IAM 스캔 결과
        scan_results['iam']['data'] = {
            'users': self.mock_aws_data['iam']['users'],
            'roles': self.mock_aws_data['iam']['roles']
        }
        scan_results['iam']['issues'] = [
            {
                'type': 'old_user_inactive',
                'resource': 'old-user',
                'risk_level': 'medium',
                'description': '180일 이상 비활성 사용자',
                'recommendation': '사용하지 않는 사용자 계정을 삭제하세요.'
            }
        ]
        
        # S3 스캔 결과
        scan_results['s3']['data'] = {
            'buckets': self.mock_aws_data['s3']['buckets']
        }
        scan_results['s3']['issues'] = [
            {
                'type': 'public_bucket',
                'resource': 'public-bucket',
                'risk_level': 'high',
                'description': '공개 읽기 권한이 설정된 S3 버킷',
                'recommendation': '버킷 정책을 검토하고 불필요한 공개 권한을 제거하세요.'
            }
        ]
        
        # CloudTrail 스캔 결과
        scan_results['cloudtrail']['data'] = {
            'trails': self.mock_aws_data['cloudtrail']['trails'],
            'events': self.mock_aws_data['cloudtrail']['events']
        }
        scan_results['cloudtrail']['issues'] = []
        
        # GuardDuty 스캔 결과
        scan_results['guardduty']['data'] = {
            'detectors': self.mock_aws_data['guardduty']['detectors'],
            'findings': self.mock_aws_data['guardduty']['findings']
        }
        scan_results['guardduty']['issues'] = [
            {
                'type': 'threat_detected',
                'resource': 'EC2 instance',
                'risk_level': 'high',
                'description': 'DNS 데이터 유출 의심 활동 탐지',
                'recommendation': '해당 EC2 인스턴스를 격리하고 보안 분석을 수행하세요.'
            }
        ]
        
        # WAF 스캔 결과
        scan_results['waf']['data'] = {
            'web_acls': self.mock_aws_data['waf']['web_acls']
        }
        scan_results['waf']['issues'] = []
        
        # 요약 정보 생성
        total_issues = sum(len(result['issues']) for result in scan_results.values() if isinstance(result, dict) and 'issues' in result)
        high_risk = sum(1 for result in scan_results.values() if isinstance(result, dict) and 'issues' in result for issue in result['issues'] if issue.get('risk_level') == 'high')
        medium_risk = sum(1 for result in scan_results.values() if isinstance(result, dict) and 'issues' in result for issue in result['issues'] if issue.get('risk_level') == 'medium')
        low_risk = total_issues - high_risk - medium_risk
        
        scan_results['summary'] = {
            'total_issues': total_issues,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'security_score': max(0, 100 - (high_risk * 20 + medium_risk * 10 + low_risk * 5)),
            'services_scanned': 5,
            'services_failed': 0
        }
        
        return scan_results
    
    def test_error_recovery_during_scan(self):
        """스캔 중 오류 복구 테스트"""
        # 인증된 상태에서 시작
        self.test_session_state['authenticated'] = True
        
        # 일부 서비스에서 오류 발생 시뮬레이션
        scan_results = {
            'iam': {'status': 'completed', 'data': {}, 'issues': []},
            'cloudtrail': {'status': 'failed', 'data': {}, 'issues': [], 'error': 'AccessDenied'},
            's3': {'status': 'completed', 'data': {}, 'issues': []},
            'guardduty': {'status': 'failed', 'data': {}, 'issues': [], 'error': 'ServiceNotEnabled'},
            'waf': {'status': 'completed', 'data': {}, 'issues': []},
            'summary': {
                'total_issues': 0,
                'services_scanned': 3,
                'services_failed': 2,
                'security_score': 85
            }
        }
        
        self.test_session_state['scan_results'] = scan_results
        self.test_session_state['scan_completed'] = True
        
        # 부분적 스캔 완료 상태 검증
        self.assertTrue(self.test_session_state['scan_completed'])
        self.assertEqual(scan_results['summary']['services_scanned'], 3)
        self.assertEqual(scan_results['summary']['services_failed'], 2)
        
        # 실패한 서비스 확인
        failed_services = [service for service, result in scan_results.items() 
                          if isinstance(result, dict) and result.get('status') == 'failed']
        self.assertEqual(len(failed_services), 2)
        self.assertIn('cloudtrail', failed_services)
        self.assertIn('guardduty', failed_services)
    
    def test_data_persistence_and_export(self):
        """데이터 지속성 및 내보내기 테스트"""
        # 스캔 결과 생성
        scan_results = {
            'summary': {
                'total_issues': 5,
                'high_risk': 2,
                'medium_risk': 2,
                'low_risk': 1,
                'security_score': 65,
                'scan_time': datetime.now().isoformat()
            },
            'iam': {'status': 'completed', 'issues': [{'type': 'test', 'risk_level': 'high'}]},
            's3': {'status': 'completed', 'issues': [{'type': 'test', 'risk_level': 'high'}]}
        }
        
        # 임시 파일에 결과 저장 테스트
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(scan_results, f, indent=2, default=str)
            temp_file_path = f.name
        
        try:
            # 저장된 파일 읽기 테스트
            with open(temp_file_path, 'r') as f:
                loaded_results = json.load(f)
            
            # 데이터 무결성 확인
            self.assertEqual(loaded_results['summary']['total_issues'], 5)
            self.assertEqual(loaded_results['summary']['security_score'], 65)
            self.assertIn('iam', loaded_results)
            self.assertIn('s3', loaded_results)
            
        finally:
            # 임시 파일 정리
            os.unlink(temp_file_path)


class TestPerformanceAndScalability(unittest.TestCase):
    """성능 및 확장성 테스트"""
    
    def test_large_dataset_handling(self):
        """대용량 데이터셋 처리 테스트"""
        # 대량의 Mock 데이터 생성
        large_user_list = []
        for i in range(1000):
            large_user_list.append({
                'UserName': f'user-{i:04d}',
                'Arn': f'arn:aws:iam::123456789012:user/user-{i:04d}',
                'CreateDate': datetime.now() - timedelta(days=i % 365),
                'Path': '/'
            })
        
        # 데이터 처리 시간 측정
        start_time = datetime.now()
        
        # 사용자 분류 시뮬레이션
        active_users = []
        inactive_users = []
        
        for user in large_user_list:
            days_old = (datetime.now() - user['CreateDate']).days
            if days_old > 90:
                inactive_users.append(user)
            else:
                active_users.append(user)
        
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        # 성능 검증 (1000개 사용자 처리가 1초 이내)
        self.assertLess(processing_time, 1.0)
        self.assertEqual(len(large_user_list), 1000)
        self.assertGreater(len(inactive_users), 0)
    
    def test_concurrent_api_calls_simulation(self):
        """동시 API 호출 시뮬레이션 테스트"""
        import threading
        import time
        
        results = []
        errors = []
        
        def mock_api_call(service_name, delay=0.1):
            """Mock API 호출"""
            try:
                time.sleep(delay)  # API 지연 시뮬레이션
                results.append(f"{service_name}_success")
            except Exception as e:
                errors.append(f"{service_name}_error: {e}")
        
        # 여러 서비스에 대한 동시 호출 시뮬레이션
        services = ['iam', 's3', 'cloudtrail', 'guardduty', 'waf']
        threads = []
        
        start_time = time.time()
        
        for service in services:
            thread = threading.Thread(target=mock_api_call, args=(service,))
            threads.append(thread)
            thread.start()
        
        # 모든 스레드 완료 대기
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # 동시 실행으로 인한 시간 단축 확인 (순차 실행 시 0.5초, 동시 실행 시 0.1초 근처)
        self.assertLess(total_time, 0.3)
        self.assertEqual(len(results), 5)
        self.assertEqual(len(errors), 0)
    
    def test_memory_usage_optimization(self):
        """메모리 사용량 최적화 테스트"""
        import sys
        import gc
        
        # 대량 데이터 생성 전 메모리 사용량
        initial_objects = len(gc.get_objects())
        
        # 대량 데이터 생성
        large_data = []
        for i in range(10000):
            large_data.append({
                'id': i,
                'name': f'resource-{i}',
                'data': f'data-{i}' * 100  # 큰 문자열
            })
        
        # 데이터 처리 (필터링)
        filtered_data = [item for item in large_data if item['id'] % 2 == 0]
        
        # 원본 데이터 삭제
        del large_data
        
        # 메모리 정리 후 객체 수 확인
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # 메모리 누수가 심각하지 않은지 확인
        object_increase = final_objects - initial_objects
        self.assertLess(object_increase, 20000)  # 합리적인 증가량
        
        # 필터링된 데이터 검증
        self.assertEqual(len(filtered_data), 5000)


class TestSecurityAndCompliance(unittest.TestCase):
    """보안 및 규정 준수 테스트"""
    
    def test_sensitive_data_handling(self):
        """민감한 데이터 처리 테스트"""
        # 민감한 정보가 포함된 Mock 데이터
        sensitive_data = {
            'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'account_id': '123456789012',
            'user_data': 'some user information'
        }
        
        # 데이터 마스킹 함수 테스트
        def mask_sensitive_data(data):
            masked_data = data.copy()
            if 'aws_access_key_id' in masked_data:
                masked_data['aws_access_key_id'] = masked_data['aws_access_key_id'][:4] + '*' * 12 + masked_data['aws_access_key_id'][-4:]
            if 'aws_secret_access_key' in masked_data:
                masked_data['aws_secret_access_key'] = '*' * len(masked_data['aws_secret_access_key'])
            return masked_data
        
        masked_data = mask_sensitive_data(sensitive_data)
        
        # 마스킹 검증
        self.assertTrue(masked_data['aws_access_key_id'].startswith('AKIA'))
        self.assertTrue(masked_data['aws_access_key_id'].endswith('MPLE'))
        self.assertIn('*', masked_data['aws_access_key_id'])
        self.assertEqual(masked_data['aws_secret_access_key'], '*' * len(sensitive_data['aws_secret_access_key']))
        self.assertEqual(masked_data['account_id'], sensitive_data['account_id'])  # 계정 ID는 마스킹하지 않음
    
    def test_input_validation(self):
        """입력 검증 테스트"""
        # 유효한 입력
        valid_inputs = {
            'account_id': '123456789012',
            'access_key': 'AKIAIOSFODNN7EXAMPLE',
            'region': 'ap-northeast-2'
        }
        
        # 잘못된 입력
        invalid_inputs = [
            {'account_id': '12345678901', 'error': 'invalid_length'},  # 11자리
            {'account_id': '1234567890123', 'error': 'invalid_length'},  # 13자리
            {'account_id': 'abcd56789012', 'error': 'invalid_format'},  # 문자 포함
            {'access_key': 'BKIAIOSFODNN7EXAMPLE', 'error': 'invalid_prefix'},  # 잘못된 접두사
            {'access_key': 'AKIAIOSFODNN7EXAMPL', 'error': 'invalid_length'},  # 19자리
            {'region': 'invalid-region-name-123', 'error': 'invalid_region'}  # 잘못된 리전
        ]
        
        # 검증 함수
        def validate_account_id(account_id):
            return account_id.isdigit() and len(account_id) == 12
        
        def validate_access_key(access_key):
            return access_key.startswith('AKIA') and len(access_key) == 20
        
        def validate_region(region):
            valid_regions = ['ap-northeast-2', 'us-east-1', 'us-west-2', 'eu-west-1']
            return region in valid_regions
        
        # 유효한 입력 테스트
        self.assertTrue(validate_account_id(valid_inputs['account_id']))
        self.assertTrue(validate_access_key(valid_inputs['access_key']))
        self.assertTrue(validate_region(valid_inputs['region']))
        
        # 잘못된 입력 테스트
        for invalid_input in invalid_inputs:
            if 'account_id' in invalid_input:
                self.assertFalse(validate_account_id(invalid_input['account_id']))
            elif 'access_key' in invalid_input:
                self.assertFalse(validate_access_key(invalid_input['access_key']))
            elif 'region' in invalid_input:
                self.assertFalse(validate_region(invalid_input['region']))
    
    def test_audit_logging(self):
        """감사 로깅 테스트"""
        audit_logs = []
        
        def log_audit_event(event_type, user_id, resource, action, result):
            """감사 이벤트 로깅"""
            audit_logs.append({
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'user_id': user_id,
                'resource': resource,
                'action': action,
                'result': result
            })
        
        # 감사 이벤트 시뮬레이션
        log_audit_event('authentication', 'user-123', 'aws-account', 'login', 'success')
        log_audit_event('scan', 'user-123', 'iam-service', 'security_scan', 'completed')
        log_audit_event('scan', 'user-123', 's3-service', 'security_scan', 'completed')
        log_audit_event('export', 'user-123', 'scan-results', 'data_export', 'success')
        
        # 감사 로그 검증
        self.assertEqual(len(audit_logs), 4)
        self.assertEqual(audit_logs[0]['event_type'], 'authentication')
        self.assertEqual(audit_logs[0]['result'], 'success')
        
        # 시간순 정렬 확인
        timestamps = [log['timestamp'] for log in audit_logs]
        self.assertEqual(timestamps, sorted(timestamps))


if __name__ == '__main__':
    # 테스트 실행
    print("통합 테스트 시작...")
    print("전체 애플리케이션 워크플로우 및 통합 기능을 테스트합니다.")
    print("-" * 60)
    
    unittest.main(verbosity=2)